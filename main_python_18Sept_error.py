#!/usr/bin/env python3
# main_python.py — BLE anti-theft system with owner/stranger logic

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
import sys
import subprocess
import json
import pyotp
import RPi.GPIO as GPIO
import alarm_system
import time
import struct
import hmac
import hashlib

from advertisement import Advertisement
from service import Application, Service, Characteristic, TwoWheelerService
from agent import NoInputNoOutputAgent

# -----------------------------
# Configuration
# -----------------------------
LOCAL_NAME = "SecureBLEPi"
TRUSTED_DEVICE_FILE = "trusted_device.json"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"

SERVICE_UUID      = "00001234-0000-1000-8000-00805f9b34fb"
TOKEN_CHAR_UUID   = "0000abcd-0000-1000-8000-00805f9b34fb"
DATA_CHAR_UUID    = "00005678-0000-1000-8000-00805f9b34fb"
CONTROL_CHAR_UUID = "0000c0de-0000-1000-8000-00805f9b34fb"

# Beacon Constants
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

# -----------------------------
# Utils
# -----------------------------
def path_to_mac(path: str) -> str:
    """Converts a D-Bus object path to a MAC address string."""
    try:
        return path.split("/")[-1].replace("dev_", "").replace("_", ":")
    except Exception:
        return str(path)

def load_trusted_device():
    """Loads the trusted device MAC address from a JSON file."""
    try:
        with open(TRUSTED_DEVICE_FILE, "r") as f:
            return json.load(f).get("device_id")
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def save_trusted_device(device_id):
    """Saves the trusted device MAC address to a JSON file."""
    try:
        with open(TRUSTED_DEVICE_FILE, "w") as f:
            json.dump({"device_id": device_id}, f)
    except Exception as e:
        print(f"⚠️ Failed to save trusted device: {e}")

last_trusted_mac = load_trusted_device()

# -----------------------------
# Beacon Helpers
# -----------------------------
def rolling_token(window=TOKEN_WINDOW, trunc_bytes=TOKEN_TRUNC_BYTES):
    """Generates a time-based rolling token for the iBeacon minor value."""
    bucket = int(time.time()) // window
    hm = hmac.new(SHARED_SECRET, str(bucket).encode(), hashlib.sha256).digest()
    return int.from_bytes(hm[:trunc_bytes], byteorder='big')

def build_ibeacon_payload():
    """Constructs the full iBeacon manufacturer data payload."""
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
        self.add_service_uuid(SERVICE_UUID)
        self.add_local_name(LOCAL_NAME)
        self.include_tx_power = True

class IBeaconAdvertisement(Advertisement):
    def __init__(self, bus, index):
        super().__init__(bus, index, "broadcast")
        payload = build_ibeacon_payload()
        self.add_manufacturer_data(IBEACON_COMPANY_ID, payload)

    def update_payload(self):
        """Rebuilds the payload and signals BlueZ that the data has changed."""
        payload = build_ibeacon_payload()
        new_mfr_data = dbus.Dictionary(
            {IBEACON_COMPANY_ID: dbus.Array(payload, signature='y')},
            signature='qay'
        )
        self.PropertiesChanged(
            "org.bluez.LEAdvertisement1",
            {"ManufacturerData": new_mfr_data},
            []
        )
        minor = (payload[20] << 8) | payload[21]
        print(f"🔁 iBeacon payload refreshed (minor={minor})")

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
        device_path = options.get("device")
        token = bytes(value).decode("utf-8", errors="ignore").strip()
        dev_mac = path_to_mac(device_path)
        print(f"🔑 Token received from {dev_mac}: {token}")

        totp = pyotp.TOTP(TOTP_SECRET)
        if totp.verify(token):
            print("✅ Valid TOTP. Access granted.")
            token_verified = True
            authorized_device_path = device_path
            last_trusted_mac = dev_mac
            save_trusted_device(dev_mac)
            alarm_system.clear_alarm()
        else:
            print("⛔ Invalid TOTP. Triggering alarm.")
            token_verified = False
            # alarm_system.trigger_alarm(buzzer_pin=18, led_pin=17)

class SecureCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        super().__init__(bus, index, DATA_CHAR_UUID, ["read", "write"], service)
        self.value = dbus.Array([], signature='y')

    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        if alarm_system.is_active():
            print("⛔ Alarm active → denying read")
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Alarm active")
        if not token_verified or options.get("device") != authorized_device_path:
            print("⛔ Unauthorized read attempt")
            alarm_system.trigger_alarm(buzzer_pin=17, led_pin=17)
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Unauthorized")
        return self.value

    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        if alarm_system.is_active():
            print("⛔ Alarm active → denying write")
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Alarm active")
        if not token_verified or options.get("device") != authorized_device_path:
            print("⛔ Unauthorized write attempt")
            alarm_system.trigger_alarm(buzzer_pin=17, led_pin=17)
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
        if alarm_system.is_active():
            print("⛔ Alarm active → denying control write")
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Alarm active")

        device = options.get("device")
        payload = bytes(value).decode("utf-8", errors="ignore").strip().lower()
        print(f"📝 ControlCharacteristic write from {path_to_mac(device)}: {payload}")

        if not token_verified or device != authorized_device_path:
            print("⛔ Unauthorized control write attempt")
            alarm_system.trigger_alarm(buzzer_pin=17, led_pin=17)
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Unauthorized")

        if payload == "clear":
            print("✅ Clearing alarm via control char")
            alarm_system.clear_alarm()

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

        self.gatt_adv = GattAdvertisement(self.bus, 0)
        self.ibeacon_adv = IBeaconAdvertisement(self.bus, 1)

    def _find_adapter(self):
        om = dbus.Interface(self.bus.get_object("org.bluez", "/"),
                            "org.freedesktop.DBus.ObjectManager")
        for path, props in om.GetManagedObjects().items():
            if "org.bluez.LEAdvertisingManager1" in props:
                return path
        return None

    def _register_advert(self, adv_obj):
        global current_adv
        self._unregister_advert()
        current_adv = adv_obj
        try:
            self.ad_manager.RegisterAdvertisement(current_adv.get_path(), {},
                reply_handler=lambda: print(f"✅ Advertisement registered: {type(adv_obj).__name__}"),
                error_handler=lambda e: print(f"❌ Ad register error: {e}"))
        except Exception as e:
            print(f"⚠️ RegisterAdvertisement exception: {e}")

    def _unregister_advert(self):
        global current_adv, adv_refresh_id
        if current_adv:
            try:
                self.ad_manager.UnregisterAdvertisement(current_adv.get_path())
            except Exception:
                pass
            current_adv = None
        
        if adv_refresh_id:
            GLib.source_remove(adv_refresh_id)
            adv_refresh_id = None

    def start_gatt_advert(self):
        print("➡️ Starting connectable GATT advertisement (normal mode)")
        self._register_advert(self.gatt_adv)

    def start_ibeacon_advert(self):
        global adv_refresh_id
        print("➡️ Switching to iBeacon advertisement (alarm mode)")
        self._register_advert(self.ibeacon_adv)

        def refresh_ibeacon_task():
            if current_adv and isinstance(current_adv, IBeaconAdvertisement):
                try:
                    current_adv.update_payload()
                except Exception as e:
                    print(f"⚠️ Failed during refresh task: {e}")
            return True

        if adv_refresh_id:
            GLib.source_remove(adv_refresh_id)
        adv_refresh_id = GLib.timeout_add_seconds(TOKEN_WINDOW, refresh_ibeacon_task)

    def run(self):
        service = BluetoothService(self.bus, 0)
        self.app.add_service(service)
        try:
            two_wheeler = TwoWheelerService(self.bus, 1)
            self.app.add_service(two_wheeler)
        except Exception as e:
            print(f"Could not add TwoWheelerService: {e}")

        self.service_manager.RegisterApplication(self.app.get_path(), {},
            reply_handler=lambda: (print("✅ GATT app registered"), self.start_gatt_advert()),
            error_handler=lambda e: (print(f"❌ Failed to register app: {e}"), sys.exit(1)))

        GLib.MainLoop().run()

    def cleanup(self):
        self._unregister_advert()
        try:
            self.service_manager.UnregisterApplication(self.app.get_path())
        except Exception:
            pass

# -----------------------------
# Connection Handling
# -----------------------------
def ensure_bonding(path, mac):
    """Checks if a device is bonded and initiates pairing if it is not."""
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

def force_disconnect_device(path):
    """Helper function to disconnect a device."""
    try:
        dev_interface = dbus.Interface(bus.get_object("org.bluez", path), "org.bluez.Device1")
        dev_interface.Disconnect()
        print(f"🔌 Forcing disconnect for {path_to_mac(path)}")
    except Exception as e:
        print(f"⚠️ Could not disconnect {path_to_mac(path)}: {e}")

def handle_trusted_reconnect(mac, path):
    """Actions to take when a trusted device reconnects."""
    global token_verified, authorized_device_path
    print(f"✅ Owner {mac} reconnected")
    alarm_system.led_continuous_glow(18, 0.5)
    authorized_device_path = path
    token_verified = True

def handle_disconnect(path):
    """Actions to take when any device disconnects."""
    global token_verified, authorized_device_path
    mac = path_to_mac(path)
    print(f"🔌 Device disconnected: {mac}")
    
    if path == authorized_device_path:
        token_verified = False
        authorized_device_path = None
        if mac == last_trusted_mac:
            print("ℹ️ Owner disconnected → stay in normal mode")
        
        app.start_gatt_advert()

def properties_changed_handler(interface, changed, invalidated, path=None):
    """D-Bus signal handler for device property changes."""
    if interface != "org.bluez.Device1" or "Connected" not in changed:
        return
    
    mac = path_to_mac(path)
    
    if changed["Connected"]:
        print(f"🔗 Device connected: {mac}")
        ensure_bonding(path, mac)
        
        if mac == last_trusted_mac:
            alarm_system.led_blink(18, 2)
            handle_trusted_reconnect(mac, path)
        else:
            print(f"⛔ Unknown device {mac} → Alarm + force disconnect")
            alarm_system.trigger_alarm(buzzer_pin=17, led_pin=17)
            force_disconnect_device(path)
    else:
        handle_disconnect(path)

def interfaces_removed_handler(path, interfaces):
    """D-Bus signal handler for when a device is removed entirely."""
    if "org.bluez.Device1" in interfaces:
        handle_disconnect(path)

# -----------------------------
# Main Execution
# -----------------------------
if __name__ == "__main__":
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    agent = NoInputNoOutputAgent(bus)
    agent_manager = dbus.Interface(bus.get_object("org.bluez", "/org/bluez"), "org.bluez.AgentManager1")
    try:
        agent_manager.RegisterAgent("/test/agent", "NoInputNoOutput")
        agent_manager.RequestDefaultAgent("/test/agent")
        print("🔑 Agent registered & set as default")
    except dbus.exceptions.DBusException as e:
        if "AlreadyExists" in str(e):
            print("🔑 Agent already registered.")
        else:
            raise

    subprocess.run(["bluetoothctl", "discoverable", "on"], check=False)
    subprocess.run(["bluetoothctl", "pairable", "on"], check=False)

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
    
    alarm_system.setup_alarm(
        on_trigger_callback=app.start_ibeacon_advert,
        on_clear_callback=app.start_gatt_advert
    )

    try:
        app.run()
    except KeyboardInterrupt:
        print("\nCaught KeyboardInterrupt. Cleaning up.")
        app.cleanup()
        GPIO.cleanup()
        sys.exit(0)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        app.cleanup()
        GPIO.cleanup()
        sys.exit(1)