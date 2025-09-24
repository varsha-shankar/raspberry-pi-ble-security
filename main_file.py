#!/usr/bin/env python3
# main_python.py — BLE anti-theft system with dual adapter support

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
import signal
import sys
import time
import struct
import hmac
import hashlib
import json
import pyotp
import RPi.GPIO as GPIO
import subprocess

from advertisement import Advertisement
from service import Application, Service, Characteristic, TwoWheelerService
from agent import NoInputNoOutputAgent

# -----------------------------
# Configuration
# -----------------------------
LOCAL_NAME = "SecureBLEPi"
BUZZER_PIN = 18
TRUSTED_DEVICE_FILE = "trusted_device.json"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"   # base32 secret

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

CONNECT_COOLDOWN = 20

# -----------------------------
# Globals
# -----------------------------
bus_gatt = None
bus_beacon = None
app = None
authorized_device_path = None
token_verified = False
last_trusted_mac = None

current_adv = None
adv_refresh_id = None
alarm_active = False

auto_reconnect_id = None
last_connect_attempt = 0
discovery_active = False

# -----------------------------
# GPIO setup
# -----------------------------
GPIO.setwarnings(False)
GPIO.setmode(GPIO.BCM)
try:
    GPIO.setup(BUZZER_PIN, GPIO.OUT)
    GPIO.output(BUZZER_PIN, GPIO.LOW)
except Exception as e:
    print(f"⚠️ GPIO setup issue: {e}")

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
        if alarm_active or not token_verified or options.get("device") != authorized_device_path:
            trigger_alarm()
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Unauthorized")
        return self.value

    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        if alarm_active or not token_verified or options.get("device") != authorized_device_path:
            trigger_alarm()
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Unauthorized")
        self.value = value
        self.PropertiesChanged("org.bluez.GattCharacteristic1", {"Value": self.value}, [])
        print("✅ Authorized write:", list(value))

class ControlCharacteristic(Characteristic):
    """Allows owner to manually clear alarm"""
    def __init__(self, bus, index, service):
        super().__init__(bus, index, CONTROL_CHAR_UUID, ["write"], service)

    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        device = options.get("device")
        payload = bytes(value).decode("utf-8", errors="ignore").strip().lower()
        if device != authorized_device_path or not token_verified:
            trigger_alarm()
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Unauthorized")
        if payload == "clear":
            print("✅ Manual alarm clear requested")
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
        global bus_gatt, bus_beacon
        self.bus_gatt = dbus.SystemBus()  # hci0
        self.bus_beacon = dbus.SystemBus()  # hci1
        bus_gatt = self.bus_gatt
        bus_beacon = self.bus_beacon

        self.app = Application(self.bus_gatt)

        self.adapter_gatt = self._find_adapter(self.bus_gatt, "hci0")
        self.adapter_beacon = self._find_adapter(self.bus_beacon, "hci1")
        if not self.adapter_gatt or not self.adapter_beacon:
            raise RuntimeError("BLE adapters not found")

        self.ad_manager_gatt = dbus.Interface(self.bus_gatt.get_object("org.bluez", self.adapter_gatt), "org.bluez.LEAdvertisingManager1")
        self.ad_manager_beacon = dbus.Interface(self.bus_beacon.get_object("org.bluez", self.adapter_beacon), "org.bluez.LEAdvertisingManager1")
        self.service_manager = dbus.Interface(self.bus_gatt.get_object("org.bluez", self.adapter_gatt), "org.bluez.GattManager1")

        # Pre-create advertisements
        try: self.gatt_adv = GattAdvertisement(self.bus_gatt, 0)
        except Exception as e: self.gatt_adv = None
        try: self.ibeacon_adv = IBeaconAdvertisement(self.bus_beacon, 1)
        except Exception as e: self.ibeacon_adv = None

    def _find_adapter(self, bus, hint):
        om = dbus.Interface(bus.get_object("org.bluez", "/"), "org.freedesktop.DBus.ObjectManager")
        for path, props in om.GetManagedObjects().items():
            if "org.bluez.LEAdvertisingManager1" in props and hint in path:
                return path
        return None

    # ---------- Advertisement Handlers ----------
    def _register_advert(self, adv_obj, manager):
        global current_adv
        self._unregister_advert()
        current_adv = adv_obj
        try:
            manager.RegisterAdvertisement(adv_obj.get_path(), {},
                                         reply_handler=lambda: print("✅ Advertisement registered"),
                                         error_handler=lambda e: print(f"❌ Ad register error: {e}"))
        except Exception as e:
            print(f"⚠️ RegisterAdvertisement exception: {e}")

    def _unregister_advert(self):
        global current_adv, adv_refresh_id
        if current_adv:
            try:
                self.ad_manager_gatt.UnregisterAdvertisement(current_adv.get_path())
            except Exception: pass
            try:
                self.ad_manager_beacon.UnregisterAdvertisement(current_adv.get_path())
            except Exception: pass
            current_adv = None
        if adv_refresh_id:
            try: GLib.source_remove(adv_refresh_id)
            except Exception: pass
            adv_refresh_id = None

    def start_gatt_advert(self):
        if not self.gatt_adv: return
        print("➡️ Starting GATT advertisement (owner connectable)")
        self._register_advert(self.gatt_adv, self.ad_manager_gatt)

    def start_ibeacon_advert(self):
        if not self.ibeacon_adv: return
        print("➡️ Switching to iBeacon advertisement (alarm)")
        self._register_advert(self.ibeacon_adv, self.ad_manager_beacon)

    # ---------- Run ----------
    def run(self):
        service = BluetoothService(self.bus_gatt, 0)
        self.app.add_service(service)
        try:
            self.app.add_service(TwoWheelerService(self.bus_gatt, 1))
        except Exception: pass

        self.service_manager.RegisterApplication(self.app.get_path(), {},
            reply_handler=lambda: (print("✅ GATT app registered"), self.start_gatt_advert()),
            error_handler=lambda e: (print(f"❌ Failed to register app: {e}"), sys.exit(1))
        )
        GLib.MainLoop().run()

    def cleanup(self):
        self._unregister_advert()
        try: self.service_manager.UnregisterApplication(self.app.get_path())
        except Exception: pass

# -----------------------------
# Alarm Handling
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
# Connection / Auto-Reconnect
# -----------------------------
def ensure_bonding(path, mac):
    try:
        dev = bus_gatt.get_object("org.bluez", path)
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
    global token_verified, authorized_device_path, auto_reconnect_id
    if mac == last_trusted_mac:
        print(f"✅ Owner {mac} reconnected")
        authorized_device_path = path
        token_verified = True
        app.start_gatt_advert()
        if auto_reconnect_id:
            GLib.source_remove(auto_reconnect_id)
            auto_reconnect_id = None

def handle_disconnect(mac, path):
    global token_verified, authorized_device_path, auto_reconnect_id
    token_verified = False
    authorized_device_path = None
    if mac == last_trusted_mac:
        print("ℹ️ Owner disconnected → auto-reconnect")
        start_discovery()
        if auto_reconnect_id is None:
            auto_reconnect_id = GLib.timeout_add_seconds(10, attempt_autoconnect)
    elif not alarm_active:
        app.start_gatt_advert()

def properties_changed_handler(interface, changed, invalidated, path=None):
    if interface != "org.bluez.Device1": return
    mac = path_to_mac(path)
    if "Connected" in changed:
        if changed["Connected"]:
            props = ensure_bonding(path, mac)
            if mac == last_trusted_mac:
                handle_trusted_reconnect(mac, path, props)
            else:
                trigger_alarm()
                try:
                    dbus.Interface(bus_gatt.get_object("org.bluez", path), "org.bluez.Device1").Disconnect()
                except Exception: pass
        else:
            handle_disconnect(mac, path)

def interfaces_removed_handler(path, interfaces):
    if "org.bluez.Device1" in interfaces:
        mac = path_to_mac(path)
        handle_disconnect(mac, path)

def start_discovery():
    global discovery_active
    if discovery_active: return
    try:
        adapter = bus_gatt.get_object("org.bluez", app.adapter_gatt)
        dbus.Interface(adapter, "org.bluez.Adapter1").StartDiscovery()
        discovery_active = True
        print("🔎 Discovery started")
    except Exception as e:
        print(f"⚠️ Could not start discovery: {e}")

def stop_discovery():
    global discovery_active
    if not discovery_active: return
    try:
        adapter = bus_gatt.get_object("org.bluez", app.adapter_gatt)
        dbus.Interface(adapter, "org.bluez.Adapter1").StopDiscovery()
        discovery_active = False
        print("🛑 Discovery stopped")
    except Exception as e:
        print(f"⚠️ Could not stop discovery: {e}")

def attempt_autoconnect():
    global last_trusted_mac, authorized_device_path, last_connect_attempt, auto_reconnect_id
    if not last_trusted_mac: return False

    om = dbus.Interface(bus_gatt.get_object("org.bluez", "/"), "org.freedesktop.DBus.ObjectManager")
    managed = om.GetManagedObjects()
    target_path, props_iface = None, None
    for path, ifaces in managed.items():
        if "org.bluez.Device1" in ifaces:
            props = ifaces["org.bluez.Device1"]
            addr = props.get("Address")
            if addr and addr.upper() == last_trusted_mac.upper():
                target_path = path
                props_iface = props
                break
    if not target_path:
        print(f"🔍 Trusted device {last_trusted_mac} not found → keep scanning")
        return True
    if props_iface.get("Connected", False):
        if auto_reconnect_id:
            GLib.source_remove(auto_reconnect_id)
            auto_reconnect_id = None
        return False
    if props_iface.get("Connecting", False):
        return True
    if not props_iface.get("Paired", False):
        print("⚠️ Trusted device not paired → cannot auto-connect")
        return False
    now = time.time()
    if now - last_connect_attempt < CONNECT_COOLDOWN:
        return True
    print(f"📱 Attempting Connect() to {last_trusted_mac} at {target_path}")
    try:
        dev = bus_gatt.get_object("org.bluez", target_path)
        dbus.Interface(dev, "org.bluez.Device1").Connect()
        last_connect_attempt = now
    except Exception as e:
        print(f"⚠️ Auto-connect failed: {e}")
    return True

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus_gatt = dbus.SystemBus()
    bus_beacon = dbus.SystemBus()

    # Register agent
    agent = NoInputNoOutputAgent(bus_gatt)
    mgr = dbus.Interface(bus_gatt.get_object("org.bluez", "/org/bluez"), "org.bluez.AgentManager1")
    try: mgr.RegisterAgent("/test/agent", "NoInputNoOutput")
    except dbus.exceptions.DBusException as e:
        if "AlreadyExists" not in str(e): raise
    mgr.RequestDefaultAgent("/test/agent")
    print("🔑 Agent registered & set as default")

    # Make discoverable/pairable
    subprocess.run(["bluetoothctl", "discoverable", "on"], check=False)
    subprocess.run(["bluetoothctl", "pairable", "on"], check=False)

    # Signal receivers
    bus_gatt.add_signal_receiver(properties_changed_handler,
                                dbus_interface="org.freedesktop.DBus.Properties",
                                signal_name="PropertiesChanged",
                                path_keyword="path")
    bus_gatt.add_signal_receiver(interfaces_removed_handler,
                                dbus_interface="org.freedesktop.DBus.ObjectManager",
                                signal_name="InterfacesRemoved")

    app = BluetoothApplication()
    try:
        app.run()
    except KeyboardInterrupt:
        app.cleanup()
        GPIO.cleanup()
        sys.exit(0)
