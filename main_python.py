# main_python.py — full working BLE anti‑theft script with token‑based authorization
# Author: Varsha Shankar (July 2025)
# ------------------------------------------------------------
# External files required in the same folder:
#   • advertisement.py  – contains Advertisement base‑class
#   • service.py        – contains Application, Service, Characteristic base‑classes
#   • agent.py          – contains NoInputNoOutputAgent class
# ------------------------------------------------------------
# This script provides:
#   • BLE peripheral advertising a primary service 1234
#   • Two characteristics inside that service:
#       – abcd : write‑only   → client sends secret token here
#       – 5678 : read / write → unlocked only after valid token
#   • Auto pairing via BlueZ Agent, device auto‑trusted after token match
#   • Anti‑theft alarm (GPIO buzzer on pin 18) when trusted device disconnects
#   • Auto‑restart advertising after disconnect
#   • Clean shutdown & GPIO cleanup on Ctrl‑C
# ------------------------------------------------------------

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
import RPi.GPIO as GPIO

from advertisement import Advertisement
from service import Application, Service, Characteristic
from agent import NoInputNoOutputAgent

# -----------------------------
# Configuration constants
# ----------------------------- 
AUTH_TOKEN = "SECRET123"          # shared secret
SERVICE_UUID = "1234"            # primary service
TOKEN_CHAR_UUID = "abcd"         # token characteristic
DATA_CHAR_UUID = "5678"          # secured characteristic
LOCAL_NAME = "SecureBLEPi"        # advertisement name
BUZZER_PIN = 18                   # GPIO pin for buzzer
TRUSTED_DEVICE_FILE = "trusted_device.json"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # 🔐 base32-encoded TOTP secret (same on Pi + app)

def load_trusted_device():
    try:
        with open(TRUSTED_DEVICE_FILE,"r") as f:
            return json.load(f).get("device_id")
    except:
        return None

# -----------------------------
# Global state flags
# -----------------------------
bus = None                         # set later
app = None                         # BluetoothApplication instance
ad_index_counter = 0               # incremented each ad restart

authorized_device_path = None      # DBus object path of trusted phone
token_verified = False             # True once phone sent correct token
last_trusted_mac = load_trusted_device()  # Persisted MAC

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
# Helper functions
# -----------------------------

def path_to_mac(path: str) -> str:
    """Convert BlueZ device object path to MAC string."""
    return path.split("/")[-1].replace("dev_", "").replace("_", ":")

def save_trusted_device(device_id):
    with open(TRUSTED_DEVICE_FILE,"W") as f:
        json.dump({"device_id":device_id},f)
        
def load_trusted_device():
    try:
        with open(TRUSTED_DEVICE_FILE,"r") as f:
            return json.load(f).get("device_id")
    except:
        return None

def trust_device(device_path: str):
    global token_verified, last_trusted_mac
    try:
        dev = bus.get_object("org.bluez", device_path)
        props = dbus.Interface(dev, "org.freedesktop.DBus.Properties")
        props.Set("org.bluez.Device1", "Trusted", dbus.Boolean(True))

        mac = path_to_mac(device_path)
        save_trusted_device(mac)
        last_trusted_mac = mac
        mac = path_to_mac(device_path)
        if token_verified:
            props.Set("org.bluez.Device1", "Trusted", dbus.Boolean(True))
            if mac != last_trusted_mac:
                save_trusted_device(mac)
                last_trusted_mac = mac
        else:
            print("⚠️ Skipping trust — token not verified")
            return

        subprocess.run(["bluetoothctl", "pairable", "off"], check=False)
        print(f"🔒 Device trusted & pairable disabled: {mac}")
        token_verified = True
    except Exception as e:
        print(f"⚠️  Could not trust device: {e}")
        token_verified = False



def trigger_alarm():
    """Sound buzzer for 3 seconds."""
    print("🚨 Anti‑theft alarm triggered!")
    GPIO.output(BUZZER_PIN, GPIO.HIGH)
    GLib.timeout_add_seconds(3, lambda *_: GPIO.output(BUZZER_PIN, GPIO.LOW) or False)

# -----------------------------
# BLE Advertisement wrapper
# -----------------------------

class BluetoothAdvertisement(Advertisement):
    def __init__(self, bus, index):
        super().__init__(bus, index, "peripheral")
        self.add_service_uuid(SERVICE_UUID)
        self.add_local_name(LOCAL_NAME)
        self.include_tx_power = True

# -----------------------------
# GATT Characteristics
# -----------------------------

class TokenCharacteristic(Characteristic):
    """Write‑only characteristic to receive the secret token."""

    def __init__(self, bus, index, service):
        super().__init__(bus, index, TOKEN_CHAR_UUID,
                         ["write", "write-without-response"], service)

    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        global authorized_device_path, token_verified
        device = options.get("device")
        token = bytes(value).decode("utf-8", errors="ignore")
        print(f"🔑 Token received from {path_to_mac(device)} → '{token}'")
        totp = pyotp.TOTP(TOTP_SECRET)
        if totp.verify(token):
            authorized_device_path = device
            trust_device(device)
            print("✅ Valid TOTP accepted. Device authorized.")
        else:
            print("⛔ Invalid TOTP. Access denied.")
            print(f"⛔ Invalid TOTP from {path_to_mac(device)}. Access denied.")
            print(f"⏱️ Server time: {int(time.time())}, expected TOTP: {totp.now()}")
            token_verified = False


class SecureCharacteristic(Characteristic):
    """Read / Write characteristic only usable after successful token."""

    def __init__(self, bus, index, service):
        super().__init__(bus, index, DATA_CHAR_UUID,
                         ["read", "write", "write-without-response", "notify"], service)
        self.value = dbus.Array([], signature='y')

    # WRITE
    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        device = options.get("device")
        if not token_verified or device != authorized_device_path:
            print(f"⛔ Unauthorized write attempt from {path_to_mac(device)}")
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized",
                                                "Write not permitted")
        self.value = value
        print(f"✅ Authorized write: {list(value)}")
        self.PropertiesChanged("org.bluez.GattCharacteristic1",
                               {"Value": self.value}, [])

    # READ
    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        device = options.get("device")
        if not token_verified or device != authorized_device_path:
            print(f"⛔ Unauthorized read attempt from {path_to_mac(device)}")
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized",
                                                "Read not permitted")
        print("✅ Authorized read")
        return self.value

# -----------------------------
# GATT Service
# -----------------------------

class BluetoothService(Service):
    def __init__(self, bus, index):
        super().__init__(bus, index, SERVICE_UUID, True)
        self.add_characteristic(TokenCharacteristic(bus, 0, self))
        self.add_characteristic(SecureCharacteristic(bus, 1, self))

# -----------------------------
# Bluetooth Application wrapper
# -----------------------------

class BluetoothApplication:
    def __init__(self):
        global bus
        self.bus = dbus.SystemBus()
        bus = self.bus  # expose to helpers
        self.app = Application(self.bus)
        self.ad_manager = None
        self.service_manager = None
        self.adapter_path = self._find_adapter()
        if not self.adapter_path:
            raise RuntimeError("BLE adapter not found")
        self._attach_managers()
        self.ad_index = 0
        self.adv = None

    def _find_adapter(self):
        om = dbus.Interface(self.bus.get_object("org.bluez", "/"),
                             "org.freedesktop.DBus.ObjectManager")
        objects = om.GetManagedObjects()
        for path, props in objects.items():
            if "org.bluez.LEAdvertisingManager1" in props:
                return path
        return None

    def _attach_managers(self):
        self.ad_manager = dbus.Interface(
            self.bus.get_object("org.bluez", self.adapter_path),
            "org.bluez.LEAdvertisingManager1")
        self.service_manager = dbus.Interface(
            self.bus.get_object("org.bluez", self.adapter_path),
            "org.bluez.GattManager1")

    # ---- Advertising helpers ----
    def start_advertising(self):
        self.ad_index += 1
        self.adv = BluetoothAdvertisement(self.bus, self.ad_index)
        print(f"📢 Start advertising (index {self.ad_index})")
        self.ad_manager.RegisterAdvertisement(
            self.adv.get_path(), {},
            reply_handler=lambda: print("✅ Advertisement registered"),
            error_handler=lambda e: print(f"❌ Ad register error: {e}"))

    def stop_advertising(self):
        if self.adv:
            try:
                self.ad_manager.UnregisterAdvertisement(self.adv.get_path())
                print("🛑 Advertisement unregistered")
            except Exception as e:
                # Already removed or never registered
                print(f"⚠️  Ad unregister: {e}")
            self.adv = None

    # ---- Run / cleanup ----
    def run(self):
        service = BluetoothService(self.bus, 0)
        print(f"🔧 Registering service UUID: {SERVICE_UUID}")
        self.app.add_service(service)
        self.app.register()
        # small delay to ensure GATT is ready
        time.sleep(1)
        self.start_advertising()
        GLib.MainLoop().run()

    def cleanup(self):
        self.stop_advertising()
        if self.app:
            try:
                self.service_manager.UnregisterApplication(self.app.get_path())
                print("🧹 GATT application unregistered")
            except Exception as e:
                print(f"⚠️  Cleanup error: {e}")

# -----------------------------
# DBus signal handlers
# -----------------------------

def properties_changed_handler(interface, changed, invalidated, path):
    global token_verified, authorized_device_path, last_trusted_mac

    if interface != "org.bluez.Device1" or "Connected" not in changed:
        return

    connected = changed["Connected"]
    mac = path_to_mac(path)

    if connected:
        print(f"🔗 Device connected: {mac}")
        if last_trusted_mac and mac != last_trusted_mac:
            print("⚠️  Unauthorized device attempted to connect!")
            trigger_alarm()

            # TODO: notify original device via BLE notify or FCM later
            try:
                dev = bus.get_object("org.bluez", path)
                dev_iface = dbus.Interface(dev, "org.bluez.Device1")
                dev_iface.Disconnect()
                print("❌ Disconnected unauthorized device")
            except Exception as e:
                print(f"⚠️  Could not disconnect: {e}")

            return  # Do not proceed with session for this device

        token_verified = False
        authorized_device_path = None
        if mac == last_trusted_mac:
            token_verified = False
            authorized_device_path = None

    else:
        print(f"🔌 Device disconnected: {mac}")
        if path == authorized_device_path and token_verified:
            trigger_alarm()
        token_verified = False
        authorized_device_path = None
        app.stop_advertising()
        app.start_advertising()


# -----------------------------
# Pairable / discoverable helper at startup
# -----------------------------

def enable_discoverable_pairable():
    subprocess.run(["bluetoothctl", "discoverable", "on"], check=False)
    subprocess.run(["bluetoothctl", "pairable", "on"], check=False)
    subprocess.run(["bluetoothctl", "agent", "NoInputNoOutput"], check=False)
    subprocess.run(["bluetoothctl", "default-agent"], check=False)
    print("✅ Pi set to discoverable & pairable (temporary)")

# -----------------------------
# Signal handlers (Ctrl‑C)
# -----------------------------

def sigterm_handler(sig, frame):
    print("🛑 Terminating, cleaning up…")
    GPIO.output(BUZZER_PIN, GPIO.LOW)
    GPIO.cleanup()
    if app:
        app.cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, sigterm_handler)
signal.signal(signal.SIGTERM, sigterm_handler)

# -----------------------------
# Main entry point
# -----------------------------

if __name__ == "__main__":
    # DBus mainloop setup
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    enable_discoverable_pairable()

    # Register BlueZ agent globally (extra safety)
    bus = dbus.SystemBus()
    agent = NoInputNoOutputAgent(bus)
    mgr = dbus.Interface(bus.get_object("org.bluez", "/org/bluez"),
                         "org.bluez.AgentManager1")
    try:
        mgr.RegisterAgent("/test/agent", "NoInputNoOutput")
    except dbus.exceptions.DBusException as e:
        if "AlreadyExists" not in str(e):
            raise
    mgr.RequestDefaultAgent("/test/agent")
    print("🔑 Agent registered & set as default")

    # Attach DBus property change listener
    bus.add_signal_receiver(properties_changed_handler,
                            dbus_interface="org.freedesktop.DBus.Properties",
                            signal_name="PropertiesChanged",
                            path="/org/bluez",
                            arg0="org.bluez.Device1",
                            sender_keyword="sender")

    # Run BLE application
    app = BluetoothApplication()
    try:
        app.run()
    except KeyboardInterrupt:
        sigterm_handler(None, None)
