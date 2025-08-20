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

# -----------------------------
# Global state flags
# -----------------------------
bus = None                         # set later
app = None                         # BluetoothApplication instance
ad_index_counter = 0               # incremented each ad restart

authorized_device_path = None      # DBus object path of trusted phone
token_verified = False             # True once phone sent correct token

def load_trusted_device():
    try:
        with open(TRUSTED_DEVICE_FILE,"r") as f:
            return json.load(f).get("device_id")
    except:
        return None

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
    print("path to mac ====",path.split("/")[-1].replace("dev_", "").replace("_", ":"))
    return path.split("/")[-1].replace("dev_", "").replace("_", ":")

def save_trusted_device(device_id):
    print("save trsuted device called and the id ===",device_id)
    with open(TRUSTED_DEVICE_FILE,"w") as f:
        json.dump({"device_id":device_id},f)

def trust_device(device_path: str):
    global token_verified, last_trusted_mac
    try:
        if not token_verified:
            print("⚠️ Skipping trust — token not verified")
            return

        dev = bus.get_object("org.bluez", device_path)
        props = dbus.Interface(dev, "org.freedesktop.DBus.Properties")

        mac = path_to_mac(device_path).strip()
        print(f"🧾 Trust request for {mac}")

        # Wait up to ~6s for pairing to settle (iOS can be slow)
        deadline = time.time() + 6.0
        paired = False
        while time.time() < deadline:
            try:
                paired = bool(props.Get("org.bluez.Device1", "Paired"))
                if paired:
                    break
            except Exception:
                pass
            time.sleep(0.25)

        print(f"🔗 Paired state for {mac}: {paired}")

        if not paired:
            print(f"⛔ {mac} not paired yet. Will not set Trusted or disable pairable.")
            return

        # Mark trusted if not already
        try:
            already_trusted = bool(props.Get("org.bluez.Device1", "Trusted"))
        except Exception:
            already_trusted = False

        if not already_trusted:
            props.Set("org.bluez.Device1", "Trusted", dbus.Boolean(True))
            print(f"✅ D-Bus Trusted set for {mac}")

        # Persist MAC if changed
        if mac and (mac != last_trusted_mac):
            save_trusted_device(mac)
            last_trusted_mac = mac

        # Best-effort bluetoothctl trust (keeps BlueZ cache consistent)
        try:
            result = subprocess.run(
                ["bluetoothctl", "--", "trust", mac],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            if result.returncode == 0:
                print(f"✅ bluetoothctl trust: {result.stdout.strip()}")
            else:
                print(f"⚠️ bluetoothctl trust failed: {result.stderr.strip()}")
        except Exception as e:
            print(f"⚠️ bluetoothctl trust exec error: {e}")

        # Now and only now, schedule pairable off
        #GLib.timeout_add_seconds(5, disable_pairable)
        #print(f"🔒 Device trusted; will disable pairable after delay for {mac}")

    except Exception as e:
        print(f"⚠️ Could not trust device: {e}")
        token_verified = False

def disable_pairable():
    try:
        # Set Adapter1.Pairable = False via D-Bus
        om = dbus.Interface(bus.get_object("org.bluez", "/"), "org.freedesktop.DBus.ObjectManager")
        objs = om.GetManagedObjects()
        adapter_path = None
        for p, ifaces in objs.items():
            if "org.bluez.Adapter1" in ifaces:
                adapter_path = p
                break
        if not adapter_path:
            print("⚠️ No adapter to disable pairable on")
            return False

        adapter = bus.get_object("org.bluez", adapter_path)
        props = dbus.Interface(adapter, "org.freedesktop.DBus.Properties")
        props.Set("org.bluez.Adapter1", "Pairable", dbus.Boolean(False))
        print("🛑 Pairable mode disabled after delay (D-Bus)")
    except Exception as e:
        print(f"⚠️ Failed to disable pairable: {e}")
    return False

def trigger_alarm():
    """Sound buzzer for 3 seconds."""
    print("🚨 Anti‑theft alarm triggered!")
    led_blink(17, 10)
    #GPIO.output(BUZZER_PIN, GPIO.HIGH)
    #GLib.timeout_add_seconds(3, lambda *_: GPIO.output(BUZZER_PIN, GPIO.LOW) or False)
        
def led_contineous_glow(pin_number, timer):
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(pin_number, GPIO.OUT)
    GPIO.output(pin_number, GPIO.HIGH)
    time.sleep(timer)
    GPIO.output(pin_number, GPIO.LOW)

def led_blink(pin_number, timer):
    end_time = time.time() + timer
    while time.time() < end_time:
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(pin_number, GPIO.OUT)
        GPIO.output(pin_number, GPIO.HIGH)
        time.sleep(0.2)
        GPIO.output(pin_number, GPIO.LOW)
        time.sleep(0.2)

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
        print("write value called on toekn characteristics")
        global authorized_device_path, token_verified
        device = options.get("device")
        device_address = path_to_mac(device)
        
          # ✅ If device is already trusted, skip TOTP
#         if mac == last_trusted_mac:
#             print(f"✅ {mac} is already trusted. Skipping TOTP check.")
#             token_verified = True
#             authorized_device_path = device
#             return
               
        token = bytes(value).decode("utf-8", errors="ignore").strip()
        print(f"🔑 Token received from {path_to_mac(device)} → '{token}'")
        
        TOTP_SECRET_BASE32 = TOTP_SECRET.upper().replace(" ", "")

        totp = pyotp.TOTP(TOTP_SECRET_BASE32)
        # Print expected OTP for debugging
        now = int(time.time())
        prev_otp = totp.at(now - 30)
        current_otp = totp.at(now)
        next_otp = totp.at(now + 30)
        print(f"📟 Acceptable OTPs: {prev_otp} (prev), {current_otp} (current), {next_otp} (next)")

        # Verify against ±1 time step
        if totp.verify(token):
            print(f"✅ Valid TOTP from {device_address}. Access granted.")
            token_verified = True
            authorized_device_path = device
            trust_device(device)
            led_contineous_glow(18, 5)
            
            # ... your access-granted code ...
        else:
            print(f"⛔ Invalid TOTP. Access denied.")
            print(f"⛔ Invalid TOTP from {device_address}. Access denied.")
            print(f"⏱️ Server time: {int(time.time())}")
            token_verified = False
            trigger_alarm()


class SecureCharacteristic(Characteristic):
    """Read / Write characteristic only usable after successful token."""

    def __init__(self, bus, index, service):
        super().__init__(bus, index, DATA_CHAR_UUID,
                         ["read", "write","write-without-response", "notify"], service)
        self.value = dbus.Array([], signature='y')
        self.notifying = False

  # NOTIFY
    @dbus.service.method("org.bluez.GattCharacteristic1")
    def StartNotify(self):
        if self.notifying:
            return
        self.notifying = True
        print("📡 Notifications started")
        GLib.timeout_add_seconds(10, self._send_heartbeat)

    @dbus.service.method("org.bluez.GattCharacteristic1")
    def StopNotify(self):
        self.notifying = False
        print("🛑 Notifications stopped")

    def _send_heartbeat(self):
        if not self.notifying:
            return False
        # Send a trivial "ping"
        self.PropertiesChanged("org.bluez.GattCharacteristic1",
                               {"Value": dbus.Array([0x01], signature='y')}, [])
        print("💓 Heartbeat notify sent")
        return True

    # WRITE
    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        device = options.get("device")
        if not token_verified or device != authorized_device_path:
            print(f"⛔ Unauthorized write attempt from {path_to_mac(device)}")
            trigger_alarm()
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
            trigger_alarm()
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

        try:
            dev = bus.get_object("org.bluez", path)
            props = dbus.Interface(dev, "org.freedesktop.DBus.Properties")
            dev_iface = dbus.Interface(dev, "org.bluez.Device1")

            # 🔑 Ensure bonding happens right away
            paired = bool(props.Get("org.bluez.Device1", "Paired"))
            if not paired:
                print(f"📌 Initiating bonding for {mac}")
                try:
                    dev_iface.Pair()   # force bonding
                except Exception as e:
                    print(f"⚠️ Bonding request error: {e}")
            else:
                print(f"✅ {mac} already bonded")

        except Exception as e:
            print(f"⚠️ Could not check bonding state: {e}")

        # Reset session state
        token_verified = False
        authorized_device_path = None


    if mac == last_trusted_mac:
            print(f"✅ Known trusted device {mac} reconnected")
            authorized_device_path = path
            token_verified = True
            try:
                if bool(props.Get("org.bluez.Device1", "Paired")):
                    trust_device(path)
            except Exception as e:
                print(f"⚠️ Could not re-check Paired state: {e}")

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
    
    # Only then enable discoverable/pairable
    enable_discoverable_pairable()

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
