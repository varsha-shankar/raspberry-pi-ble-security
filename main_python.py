#!/usr/bin/env python3
# main_python.py — BLE anti-theft: connectable GATT + switch-to-iBeacon on alarm
# Improved registration / unregister flow, rolling token, control characteristic.
# Keep your existing advertisement.py, service.py, agent.py files.
# -----------------------------------------------------------------------------

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
import signal
import sys
import time
import subprocess
import json
import pyotp
import os
import struct
import hmac
import hashlib
import RPi.GPIO as GPIO

from advertisement import Advertisement
from service import Application, Service, Characteristic, TwoWheelerService
from agent import NoInputNoOutputAgent

# -----------------------------
# Configuration
# -----------------------------
LOCAL_NAME = "SecureBLEPi"                     # full name; advert uses shortened form
BUZZER_PIN = 18
TRUSTED_DEVICE_FILE = "trusted_device.json"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"

# GATT (full 128-bit service/char UUIDs)
SERVICE_UUID          = "00001234-0000-1000-8000-00805f9b34fb"
TOKEN_CHAR_UUID       = "0000abcd-0000-1000-8000-00805f9b34fb"
DATA_CHAR_UUID        = "00005678-0000-1000-8000-00805f9b34fb"
CONTROL_CHAR_UUID     = "0000c0de-0000-1000-8000-00805f9b34fb"

# iBeacon / rolling token config
IBEACON_COMPANY_ID = 0x004C
BEACON_UUID = SERVICE_UUID
SHARED_SECRET = b"super_secret_key"
TOKEN_WINDOW = 30
TOKEN_TRUNC_BYTES = 2
TX_POWER = -59

# Beacon duration (0 = indefinite until cleared)
BEACON_DURATION = 0

# -----------------------------
# Globals / state
# -----------------------------
bus = None
app = None

authorized_device_path = None
token_verified = False

current_adv = None            # currently registered Advertisement object
adv_refresh_id = None         # GLib timer id for rotating token
alarm_active = False
beacon_timeout_id = None

# -----------------------------
# Utilities
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
        print(f"⚠️ Failed to persist trusted device: {e}")

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
# Beacon helpers (rolling HMAC -> minor)
# -----------------------------
def rolling_token(window=TOKEN_WINDOW, trunc_bytes=TOKEN_TRUNC_BYTES):
    bucket = int(time.time()) // window
    hm = hmac.new(SHARED_SECRET, str(bucket).encode(), hashlib.sha256).digest()
    return int.from_bytes(hm[:trunc_bytes], byteorder='big')

def build_ibeacon_payload():
    """
    iBeacon layout:
    [0..1]   = 0x0215
    [2..17]  = 16-byte UUID
    [18..19] = major
    [20..21] = minor (rolling token)
    [22]     = tx power
    """
    uuid_bytes = bytes.fromhex(BEACON_UUID.replace("-", ""))
    if len(uuid_bytes) != 16:
        raise ValueError("UUID must be 16 bytes")
    major = 1
    minor = rolling_token()
    payload = struct.pack(">H16sHHb", 0x0215, uuid_bytes, major, minor, TX_POWER)
    return list(payload)

# -----------------------------
# Advertisement classes
# -----------------------------
class GattAdvertisement(Advertisement):
    """
    Connectable advertisement (normal operation).
    Advertises short 16-bit UUID '1234' + short name + 2-byte rolling token in ManufacturerData.
    """
    def __init__(self, bus, index):
        super().__init__(bus, index, "peripheral")
        # short 16-bit UUID for scan-time filtering (saves space)
        self.add_service_uuid("1234")
        # very short local name to save AD space
        self.add_local_name(LOCAL_NAME[:6])
        self.include_tx_power = True
        # attach small rolling token
        token_int = rolling_token()
        token_bytes = token_int.to_bytes(TOKEN_TRUNC_BYTES, "big")
        self.add_manufacturer_data(IBEACON_COMPANY_ID, list(token_bytes))

class IBeaconAdvertisement(Advertisement):
    """
    Strict iBeacon advertisement: non-connectable broadcast with full iBeacon payload.
    Use only while in alarm mode.
    """
    def __init__(self, bus, index):
        super().__init__(bus, index, "broadcast")
        payload = build_ibeacon_payload()
        self.add_manufacturer_data(IBEACON_COMPANY_ID, payload)

# -----------------------------
# GATT Characteristics & Service
# -----------------------------
class TokenCharacteristic(Characteristic):
    """Write-only characteristic where phone sends TOTP string (ASCII)."""
    def __init__(self, bus, index, service):
        super().__init__(bus, index, TOKEN_CHAR_UUID, ["write", "write-without-response"], service)

    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        global token_verified, authorized_device_path
        device = options.get("device")
        dev_mac = path_to_mac(device)
        token = bytes(value).decode("utf-8", errors="ignore").strip()
        print(f"🔑 Token received: '{token}' from {dev_mac}")

        TOTP_SECRET_BASE32 = TOTP_SECRET.upper().replace(" ", "")
        totp = pyotp.TOTP(TOTP_SECRET_BASE32)
        if totp.verify(token):
            print("✅ Valid TOTP. Access granted.")
            token_verified = True
            authorized_device_path = device
            save_trusted_device(dev_mac)
        else:
            print("⛔ Invalid TOTP. Triggering alarm.")
            token_verified = False
            trigger_alarm()

class SecureCharacteristic(Characteristic):
    """Protected read/write characteristic unlocked after token verification."""
    def __init__(self, bus, index, service):
        super().__init__(bus, index, DATA_CHAR_UUID, ["read", "write", "write-without-response", "notify"], service)
        self.value = dbus.Array([], signature='y')
        self.notifying = False

    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        device = options.get("device")
        if not token_verified or device != authorized_device_path:
            print("⛔ Unauthorized write attempt")
            trigger_alarm()
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Write not permitted")
        self.value = value
        print("✅ Authorized write:", list(value))
        self.PropertiesChanged("org.bluez.GattCharacteristic1", {"Value": self.value}, [])

    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        device = options.get("device")
        if not token_verified or device != authorized_device_path:
            print("⛔ Unauthorized read attempt")
            trigger_alarm()
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Read not permitted")
        print("✅ Authorized read")
        return self.value

class ControlCharacteristic(Characteristic):
    """
    Control point for alarm management.
    - Write 'clear' to stop beaconing (only by authorized device).
    - Optional: could add 'trigger' to remotely trigger.
    """
    def __init__(self, bus, index, service):
        super().__init__(bus, index, CONTROL_CHAR_UUID, ["write"], service)

    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        global authorized_device_path, token_verified
        device = options.get("device")
        payload = bytes(value).decode("utf-8", errors="ignore").strip().lower()
        print(f"📝 Control write from {path_to_mac(device)}: {payload}")

        if not token_verified or device != authorized_device_path:
            print("⛔ Unauthorized control write attempt")
            trigger_alarm()
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Control not permitted")

        if payload == "clear":
            print("✅ Authorized request: clearing alarm")
            clear_alarm()
        elif payload == "trigger":
            print("✅ Authorized request: triggering alarm (manual)")
            trigger_alarm()
        else:
            print(f"⚠️ Unknown control command: {payload}")

class BluetoothService(Service):
    def __init__(self, bus, index):
        super().__init__(bus, index, SERVICE_UUID, True)
        self.add_characteristic(TokenCharacteristic(bus, 0, self))
        self.add_characteristic(SecureCharacteristic(bus, 1, self))
        self.add_characteristic(ControlCharacteristic(bus, 2, self))

# -----------------------------
# Bluetooth application and advert control
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

        self.current_adv = None

    def _find_adapter(self):
        om = dbus.Interface(self.bus.get_object("org.bluez", "/"), "org.freedesktop.DBus.ObjectManager")
        objects = om.GetManagedObjects()
        for path, props in objects.items():
            if "org.bluez.LEAdvertisingManager1" in props:
                return path
        return None

    def _register_advert(self, adv_obj):
        """Unregister existing advert, register adv_obj and keep reference."""
        global current_adv
        # Unregister existing advert first (tolerate errors)
        self._unregister_advert()
        current_adv = adv_obj
        try:
            # Register asynchronously; reply/error handlers print status
            self.ad_manager.RegisterAdvertisement(
                current_adv.get_path(), {},
                reply_handler=lambda: print("✅ Advertisement registered"),
                error_handler=lambda e: print(f"❌ Ad register error: {e}")
            )
        except Exception as e:
            print(f"⚠️ RegisterAdvertisement exception: {e}")
            print("↳ Check `sudo journalctl -u bluetooth -f` for details.")

    def _unregister_advert(self):
        global current_adv, adv_refresh_id
        if current_adv:
            try:
                self.ad_manager.UnregisterAdvertisement(current_adv.get_path())
                print("🛑 Advertisement unregistered")
            except Exception as e:
                # common if it was never registered or already removed
                print(f"⚠️ Ad unregister error (ignored): {e}")
            current_adv = None
        # stop refresh timer if any
        if adv_refresh_id:
            try:
                GLib.source_remove(adv_refresh_id)
            except Exception:
                pass

    def start_gatt_advert(self):
        """Start connectable GATT advertisement (normal mode)."""
        print("➡️ Starting connectable GATT advertisement (normal mode)")
        adv = GattAdvertisement(self.bus, 0)
        # Small delay before registering (helps controller settle after unregister)
        GLib.timeout_add(200, lambda: (self._register_advert(adv), False)[1])

        # Start token refresh timer
        def refresh_gatt_token():
            global current_adv
            if not current_adv or not isinstance(current_adv, GattAdvertisement):
                return False
            try:
                token_int = rolling_token()
                token_bytes = token_int.to_bytes(TOKEN_TRUNC_BYTES, "big")
                current_adv.add_manufacturer_data(IBEACON_COMPANY_ID, list(token_bytes))
                print(f"🔁 GATT adv token updated: {token_int}")
            except Exception as e:
                print(f"⚠️ Failed to refresh GATT token: {e}")
            return True

        global adv_refresh_id
        # ensure any previous timer cleared
        if adv_refresh_id:
            try:
                GLib.source_remove(adv_refresh_id)
            except Exception:
                pass
            adv_refresh_id = None
        adv_refresh_id = GLib.timeout_add_seconds(TOKEN_WINDOW, refresh_gatt_token)

    def start_ibeacon_advert(self):
        """Start strict iBeacon advertisement (alarm mode)."""
        print("➡️ Switching to iBeacon advert (alarm mode)")
        adv = IBeaconAdvertisement(self.bus, 1)
        # small delay to reduce register/unregister races
        GLib.timeout_add(200, lambda: (self._register_advert(adv), False)[1])

        def refresh_ibeacon():
            global current_adv
            if not current_adv or not isinstance(current_adv, IBeaconAdvertisement):
                return False
            try:
                payload = build_ibeacon_payload()
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

    def enable_alarm_beacon(self):
        global alarm_active, beacon_timeout_id
        alarm_active = True
        self.start_ibeacon_advert()
        if BEACON_DURATION and BEACON_DURATION > 0:
            if beacon_timeout_id:
                try:
                    GLib.source_remove(beacon_timeout_id)
                except Exception:
                    pass
            beacon_timeout_id = GLib.timeout_add_seconds(BEACON_DURATION, lambda *_: clear_alarm())

    def disable_alarm_beacon(self):
        global alarm_active, beacon_timeout_id
        alarm_active = False
        if beacon_timeout_id:
            try:
                GLib.source_remove(beacon_timeout_id)
            except Exception:
                pass
        beacon_timeout_id = None
        self.start_gatt_advert()

    def run(self):
        service = BluetoothService(self.bus, 0)
        # Try to add the TwoWheeler simulator service (if available)
        try:
            two_wheeler = TwoWheelerService(self.bus, 1)
            self.app.add_service(two_wheeler)
        except Exception:
            pass

        self.app.add_service(service)

        def _app_registered():
            print("✅ GATT app registered")
            # start normal connectable advert
            self.start_gatt_advert()

        def _app_error(e):
            print(f"❌ Failed to register GATT app: {e}")
            print("↳ See `sudo journalctl -u bluetooth -f` for details.")
            sys.exit(1)

        self.service_manager.RegisterApplication(self.app.get_path(), {}, reply_handler=_app_registered,
                                                 error_handler=_app_error)

        GLib.MainLoop().run()

    def cleanup(self):
        print("🧹 Cleaning up BluetoothApplication")
        self._unregister_advert()
        try:
            self.service_manager.UnregisterApplication(self.app.get_path())
        except Exception as e:
            print(f"⚠️ GATT unregister error (ignored): {e}")

# -----------------------------
# Alarm control functions
# -----------------------------
def trigger_alarm():
    """Trigger theft alarm: sound buzzer briefly and start iBeacon advert."""
    global app
    print("🚨 Alarm triggered! Switching to beacon mode.")
    try:
        GPIO.output(BUZZER_PIN, GPIO.HIGH)
        GLib.timeout_add_seconds(3, lambda *_: GPIO.output(BUZZER_PIN, GPIO.LOW) or False)
    except Exception:
        pass
    if app:
        app.enable_alarm_beacon()

def clear_alarm():
    """Clear alarm and restore connectable GATT advert."""
    global app
    print("✅ Alarm cleared. Restoring normal connectable advertisement.")
    try:
        GPIO.output(BUZZER_PIN, GPIO.LOW)
    except Exception:
        pass
    if app:
        app.disable_alarm_beacon()

# -----------------------------
# DBus property change listener (optional)
# -----------------------------
def properties_changed_handler(interface, changed, invalidated, path):
    # monitor device connect/disconnect events (optional behavior)
    if interface != "org.bluez.Device1" or "Connected" not in changed:
        return
    connected = changed["Connected"]
    mac = path_to_mac(path)
    if connected:
        print(f"🔗 Device connected: {mac}")
    else:
        print(f"🔌 Device disconnected: {mac}")
        # optional: automatically trigger alarm when trusted device unexpectedly disconnects
        # if path == authorized_device_path and token_verified:
        #     trigger_alarm()

# -----------------------------
# Startup / main
# -----------------------------
if __name__ == "__main__":
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    # Register agent
    agent = NoInputNoOutputAgent(bus)
    mgr = dbus.Interface(bus.get_object("org.bluez", "/org/bluez"), "org.bluez.AgentManager1")
    try:
        mgr.RegisterAgent("/test/agent", "NoInputNoOutput")
    except dbus.exceptions.DBusException as e:
        if "AlreadyExists" not in str(e):
            raise
    mgr.RequestDefaultAgent("/test/agent")
    print("🔑 Agent registered")

    # Make adapter discoverable/pairable for pairing flows
    subprocess.run(["bluetoothctl", "discoverable", "on"], check=False)
    subprocess.run(["bluetoothctl", "pairable", "on"], check=False)

    # Attach property change listener
    bus.add_signal_receiver(properties_changed_handler,
                            dbus_interface="org.freedesktop.DBus.Properties",
                            signal_name="PropertiesChanged",
                            path="/org/bluez",
                            arg0="org.bluez.Device1")

    # create app and run
    app = BluetoothApplication()
    try:
        app.run()
    except KeyboardInterrupt:
        try:
            app.cleanup()
        except Exception:
            pass
        GPIO.cleanup()
        sys.exit(0)
