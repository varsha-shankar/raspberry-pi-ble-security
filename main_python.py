#!/usr/bin/env python3
# main_python.py — BLE anti-theft system with owner/stranger logic

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
import signal
import sys
import time
import subprocess
import struct
import hmac
import hashlib
import json
import pyotp
import RPi.GPIO as GPIO

from advertisement import Advertisement
from service import Application, Service, Characteristic, TwoWheelerService
from agent import NoInputNoOutputAgent

# -----------------------------
# Configuration
# -----------------------------
LOCAL_NAME = "SecureBLEPi"
BUZZER_PIN = 18
TRUSTED_DEVICE_FILE = "trusted_device.json"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"   # base32 secret (used by phone app)

SERVICE_UUID      = "00001234-0000-1000-8000-00805f9b34fb"
TOKEN_CHAR_UUID   = "0000abcd-0000-1000-8000-00805f9b34fb"
DATA_CHAR_UUID    = "00005678-0000-1000-8000-00805f9b34fb"
CONTROL_CHAR_UUID = "0000c0de-0000-1000-8000-00805f9b34fb"

IBEACON_COMPANY_ID = 0x004C
BEACON_UUID = SERVICE_UUID
SHARED_SECRET = b"super_secret_key"
TOKEN_WINDOW = 30
TOKEN_TRUNC_BYTES = 2
TX_POWER = -59

# -----------------------------
# Globals
# -----------------------------
bus = None
app = None
authorized_device_path = None
token_verified = False
last_trusted_mac = None

current_adv = None
adv_refresh_id = None

alarm_active = False

# -----------------------------
# GPIO setup
# -----------------------------
GPIO.setwarnings(False)
GPIO.setmode(GPIO.BCM)
try:
    GPIO.setup(BUZZER_PIN, GPIO.OUT)
    GPIO.output(BUZZER_PIN, GPIO.LOW)
except Exception as e:
    print(f"⚠️  GPIO setup issue: {e}")

# -----------------------------
# Utils
# -----------------------------
def path_to_mac(path: str) -> str:
    try:
        return path.split("/")[-1].replace("dev_", "").replace("_", ":")
    except Exception:
        return str(path)

def load_trusted_device():
    try:
        with open(TRUSTED_DEVICE_FILE, "r") as f:
            return json.load(f).get("device_id")
    except Exception:
        return None

def save_trusted_device(device_id):
    try:
        with open(TRUSTED_DEVICE_FILE, "w") as f:
            json.dump({"device_id": device_id}, f)
    except Exception as e:
        print(f"⚠️ Failed to save trusted device: {e}")

last_trusted_mac = load_trusted_device()

# -----------------------------
# Beacon helpers
# -----------------------------
def rolling_token(window=TOKEN_WINDOW, trunc_bytes=TOKEN_TRUNC_BYTES):
    bucket = int(time.time()) // window
    hm = hmac.new(SHARED_SECRET, str(bucket).encode(), hashlib.sha256).digest()
    return int.from_bytes(hm[:trunc_bytes], byteorder='big')

def build_ibeacon_payload():
    uuid_bytes = bytes.fromhex(BEACON_UUID.replace("-", ""))
    major = 1
    minor = rolling_token()
    payload = struct.pack(">H16sHHb", 0x0215, uuid_bytes, major, minor, TX_POWER)
    return list(payload)

# -----------------------------
# Advertisements
# -----------------------------
class GattAdvertisement(Advertisement):
    def __init__(self, bus, index):
        super().__init__(bus, index, "peripheral")
        self.add_service_uuid("1234")
        self.add_local_name(LOCAL_NAME[:8])
        self.include_tx_power = True

class IBeaconAdvertisement(Advertisement):
    def __init__(self, bus, index):
        super().__init__(bus, index, "broadcast")
        payload = build_ibeacon_payload()
        self.add_manufacturer_data(IBEACON_COMPANY_ID, payload)

# -----------------------------
# GATT Characteristics
# -----------------------------
class TokenCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        super().__init__(bus, index, TOKEN_CHAR_UUID, ["write"], service)

    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        global token_verified, authorized_device_path, last_trusted_mac
        device = options.get("device")
        token = bytes(value).decode("utf-8", errors="ignore").strip()
        dev_mac = path_to_mac(device)
        print(f"🔑 Token received from {dev_mac}: {token}")

        totp = pyotp.TOTP(TOTP_SECRET)
        if totp.verify(token):
            print("✅ Valid TOTP. Access granted.")
            token_verified = True
            authorized_device_path = device
            last_trusted_mac = dev_mac
            save_trusted_device(dev_mac)
            clear_alarm()
        else:
            print("⛔ Invalid TOTP. Triggering alarm.")
            token_verified = False
            trigger_alarm()

class SecureCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        super().__init__(bus, index, DATA_CHAR_UUID, ["read", "write"], service)
        self.value = dbus.Array([], signature='y')

    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        if alarm_active:
            print("⛔ Alarm active → denying read")
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Alarm active")
        if not token_verified or options.get("device") != authorized_device_path:
            print("⛔ Unauthorized read attempt")
            trigger_alarm()
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Unauthorized")
        return self.value

    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        if alarm_active:
            print("⛔ Alarm active → denying write")
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Alarm active")
        if not token_verified or options.get("device") != authorized_device_path:
            print("⛔ Unauthorized write attempt")
            trigger_alarm()
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Unauthorized")
        self.value = value
        print("✅ Authorized write:", list(value))
        self.PropertiesChanged("org.bluez.GattCharacteristic1", {"Value": self.value}, [])

class ControlCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        super().__init__(bus, index, CONTROL_CHAR_UUID, ["write"], service)

    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        if alarm_active:
            print("⛔ Alarm active → denying control write")
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Alarm active")

        device = options.get("device")
        payload = bytes(value).decode("utf-8", errors="ignore").strip().lower()
        print(f"📝 ControlCharacteristic write from {path_to_mac(device)}: {payload}")

        if not token_verified or device != authorized_device_path:
            print("⛔ Unauthorized control write attempt")
            trigger_alarm()
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Unauthorized")

        if payload == "clear":
            print("✅ Clearing alarm via control char")
            clear_alarm()

# -----------------------------
# Bluetooth Service
# -----------------------------
class BluetoothService(Service):
    def __init__(self, bus, index):
        super().__init__(bus, index, SERVICE_UUID, True)
        self.add_characteristic(TokenCharacteristic(bus, 0, self))
        self.add_characteristic(SecureCharacteristic(bus, 1, self))
        self.add_characteristic(ControlCharacteristic(bus, 2, self))

# -----------------------------
# Bluetooth Application
# -----------------------------
class BluetoothApplication:
    def __init__(self):
        global bus
        self.bus = dbus.SystemBus()
        bus = self.bus
        self.app = Application(self.bus)

        self.adapter_path = self._find_adapter()
        if not self.adapter_path:
            raise RuntimeError("BLE adapter not found")

        self.ad_manager = dbus.Interface(self.bus.get_object("org.bluez", self.adapter_path),
                                         "org.bluez.LEAdvertisingManager1")
        self.service_manager = dbus.Interface(self.bus.get_object("org.bluez", self.adapter_path),
                                             "org.bluez.GattManager1")

        # -------------------------
        # Create advertisement objects ONCE and reuse them (Option 1)
        # This prevents repeated dbus.service.Object registration errors.
        # -------------------------
        try:
            # create and keep the advertisement objects so they are not re-added repeatedly
            self.gatt_adv = GattAdvertisement(self.bus, 0)
        except Exception as e:
            # if creating fails, log but continue; creation usually registers the object path
            print(f"⚠️ Could not create GATT advert object at init: {e}")
            self.gatt_adv = None

        try:
            self.ibeacon_adv = IBeaconAdvertisement(self.bus, 1)
        except Exception as e:
            print(f"⚠️ Could not create iBeacon advert object at init: {e}")
            self.ibeacon_adv = None

    def _find_adapter(self):
        om = dbus.Interface(self.bus.get_object("org.bluez", "/"),
                            "org.freedesktop.DBus.ObjectManager")
        for path, props in om.GetManagedObjects().items():
            if "org.bluez.LEAdvertisingManager1" in props:
                return path
        return None

    def _register_advert(self, adv_obj):
        global current_adv
        # Unregister existing advertisement slot (keeps single-slot controller semantics)
        self._unregister_advert()
        current_adv = adv_obj
        try:
            self.ad_manager.RegisterAdvertisement(current_adv.get_path(), {},
                reply_handler=lambda: print("✅ Advertisement registered"),
                error_handler=lambda e: print(f"❌ Ad register error: {e}"))
        except Exception as e:
            print(f"⚠️ RegisterAdvertisement exception: {e}")

    def _unregister_advert(self):
        global current_adv, adv_refresh_id
        if current_adv:
            try:
                self.ad_manager.UnregisterAdvertisement(current_adv.get_path())
                print("🛑 Advertisement unregistered")
            except Exception:
                pass
            # do NOT delete the advertisement object — we reuse the instance
            current_adv = None
        if adv_refresh_id:
            try: GLib.source_remove(adv_refresh_id)
            except Exception: pass
            adv_refresh_id = None

    def start_gatt_advert(self):
        # Reuse the pre-created gatt_adv object instead of creating a new one each time.
        if not self.gatt_adv:
            # fallback: create if it wasn't created at init
            try:
                self.gatt_adv = GattAdvertisement(self.bus, 0)
            except Exception as e:
                print(f"⚠️ Failed to create GATT advert on demand: {e}")
                return

        print("➡️ Starting connectable GATT advertisement (normal mode)")
        self._register_advert(self.gatt_adv)

        def refresh_gatt_token():
            # Keep advertisement minimal
            return True

        global adv_refresh_id
        if adv_refresh_id:
            try:
                GLib.source_remove(adv_refresh_id)
            except Exception:
                pass
        adv_refresh_id = GLib.timeout_add_seconds(TOKEN_WINDOW, refresh_gatt_token)

    def start_ibeacon_advert(self):
        # Reuse the pre-created ibeacon_adv object instead of creating a new one each time.
        if not self.ibeacon_adv:
            try:
                self.ibeacon_adv = IBeaconAdvertisement(self.bus, 1)
            except Exception as e:
                print(f"⚠️ Failed to create iBeacon advert on demand: {e}")
                return

        print("➡️ Switching to iBeacon advertisement (alarm mode)")
        self._register_advert(self.ibeacon_adv)

        def refresh_ibeacon():
            try:
                payload = build_ibeacon_payload()
                # Replace manufacturer data in-place by re-adding
                current_adv.add_manufacturer_data(IBEACON_COMPANY_ID, payload)
                minor = (payload[20] << 8) | payload[21]
                print(f"🔁 iBeacon payload refreshed (minor={minor})")
            except Exception as e:
                print(f"⚠️ Failed to refresh iBeacon payload: {e}")
            return True

        global adv_refresh_id
        if adv_refresh_id:
            try:
                GLib.source_remove(adv_refresh_id)
            except Exception:
                pass
        adv_refresh_id = GLib.timeout_add_seconds(TOKEN_WINDOW, refresh_ibeacon)

    def run(self):
        service = BluetoothService(self.bus, 0)
        self.app.add_service(service)
        try:
            two_wheeler = TwoWheelerService(self.bus, 1)
            self.app.add_service(two_wheeler)
        except Exception:
            pass

        self.service_manager.RegisterApplication(self.app.get_path(), {},
            reply_handler=lambda: (print("✅ GATT app registered"), self.start_gatt_advert()),
            error_handler=lambda e: (print(f"❌ Failed to register app: {e}"), sys.exit(1)))

        GLib.MainLoop().run()

    def cleanup(self):
        self._unregister_advert()
        try: self.service_manager.UnregisterApplication(self.app.get_path())
        except Exception: pass

# -----------------------------
# Alarm
# -----------------------------
def trigger_alarm():
    global alarm_active
    if alarm_active: return
    alarm_active = True
    print("🚨 Alarm triggered! Switching to iBeacon mode.")
    try:
        GPIO.output(BUZZER_PIN, GPIO.HIGH)
        GLib.timeout_add_seconds(3, lambda *_: GPIO.output(BUZZER_PIN, GPIO.LOW) or False)
    except Exception: pass
    app.start_ibeacon_advert()

def clear_alarm():
    global alarm_active
    if not alarm_active:
        try: app.start_gatt_advert()
        except Exception: pass
        return
    alarm_active = False
    print("✅ Alarm cleared. Back to normal mode.")
    app.start_gatt_advert()

# -----------------------------
# Connection Handling
# -----------------------------
def ensure_bonding(path, mac):
    try:
        dev = bus.get_object("org.bluez", path)
        props = dbus.Interface(dev, "org.freedesktop.DBus.Properties")
        paired = bool(props.Get("org.bluez.Device1", "Paired"))
        if not paired:
            print(f"📌 Initiating bonding for {mac}")
            dbus.Interface(dev, "org.bluez.Device1").Pair()
        return props
    except Exception as e:
        print(f"⚠️ Bonding check failed: {e}")
        return None

def handle_trusted_reconnect(mac, path, props):
    global token_verified, authorized_device_path
    if mac == last_trusted_mac:
        print(f"✅ Owner {mac} reconnected")
        authorized_device_path = path
        token_verified = True

def handle_disconnect(mac, path):
    global token_verified, authorized_device_path
    print(f"🔌 Device disconnected: {mac}")
    token_verified = False
    authorized_device_path = None
    if mac == last_trusted_mac:
        print("ℹ️ Owner disconnected → stay in normal mode")
        app.start_gatt_advert()
    elif not alarm_active:
        app.start_gatt_advert()

def properties_changed_handler(interface, changed, invalidated, path=None):
    if interface != "org.bluez.Device1": return
    mac = path_to_mac(path)

    if "Connected" in changed:
        if changed["Connected"]:
            print(f"🔗 Device connected: {mac}")
            props = ensure_bonding(path, mac)
            if mac == last_trusted_mac:
                print("✅ Trusted device connected")
                handle_trusted_reconnect(mac, path, props)
            else:
                print(f"⛔ Unknown device {mac} → Alarm + force disconnect")
                trigger_alarm()
                try:
                    dbus.Interface(bus.get_object("org.bluez", path), "org.bluez.Device1").Disconnect()
                except Exception as e:
                    print(f"⚠️ Could not disconnect {mac}: {e}")
        else:
            handle_disconnect(mac, path)

def interfaces_removed_handler(path, interfaces):
    if "org.bluez.Device1" in interfaces:
        mac = path_to_mac(path)
        print(f"🗑️ InterfacesRemoved: {mac}")
        handle_disconnect(mac, path)

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    agent = NoInputNoOutputAgent(bus)
    mgr = dbus.Interface(bus.get_object("org.bluez", "/org/bluez"), "org.bluez.AgentManager1")
    try: mgr.RegisterAgent("/test/agent", "NoInputNoOutput")
    except dbus.exceptions.DBusException as e:
        if "AlreadyExists" not in str(e): raise
    mgr.RequestDefaultAgent("/test/agent")
    print("🔑 Agent registered & set as default")

    subprocess.run(["bluetoothctl", "discoverable", "on"], check=False)
    subprocess.run(["bluetoothctl", "pairable", "on"], check=False)

    # 🔎 Signal receivers
    bus.add_signal_receiver(
        properties_changed_handler,
        dbus_interface="org.freedesktop.DBus.Properties",
        signal_name="PropertiesChanged",
        path_keyword="path"
    )
    bus.add_signal_receiver(
        interfaces_removed_handler,
        dbus_interface="org.freedesktop.DBus.ObjectManager",
        signal_name="InterfacesRemoved"
    )
    print("🔎 DBus signal receivers registered (PropertiesChanged, InterfacesRemoved)")

    app = BluetoothApplication()
    try:
        app.run()
    except KeyboardInterrupt:
        app.cleanup()
        GPIO.cleanup()
        sys.exit(0)
