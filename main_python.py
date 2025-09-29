#!/usr/bin/env python3
# main_python.py — BLE anti-theft system with owner/stranger logic

from gpiozero.pins.pigpio import PiGPIOFactory
from gpiozero import Button, DigitalOutputDevice

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
import signal
import sys
import time
import subprocess
import re
import struct
import hmac
import hashlib
import json
import pyotp

from advertisement import Advertisement
from service import Application, Service, Characteristic, TwoWheelerService, TwoWheelerCharID, char_values
from agent import NoInputNoOutputAgent

# -----------------------------
# Configuration
# -----------------------------
LOCAL_NAME = "SecureBLEPi"
IGNITION_PIN = 18
BUZZER_PIN = 17
PUSH_BUTTON_PIN = 27 
TRUSTED_DEVICE_FILE = "trusted_device.json"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"

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

RESET_PIN = 24

# -----------------------------
# Globals & GPIO Initialization
# -----------------------------
bus = None
app = None
authorized_device_path = None
token_verified = False
last_trusted_mac = None
current_adv = None
adv_refresh_id = None
alarm_active = False
ignition_status = False
auto_reconnect_id = None
last_connect_attempt = 0
CONNECT_COOLDOWN = 15
discovery_active = False
connecting_attempt = False
ignition_characteristic_obj = None

# --- GPIOZERO SETUP ---
try:
    factory = PiGPIOFactory()
    ignition_led = DigitalOutputDevice(IGNITION_PIN, pin_factory=factory)
    print(f"💡 Ignition LED initialized on GPIO {IGNITION_PIN} using pigpio factory.")
    
    buzzer = DigitalOutputDevice(BUZZER_PIN, pin_factory=factory)
    print(f"🔊 Buzzer initialized on GPIO {BUZZER_PIN} using pigpio factory.")
except Exception as e:
    print(f"⚠️ Could not initialize pigpio factory. Is the daemon running? (sudo systemctl start pigpiod)")
    print(f"   Error: {e}")
    factory = None
    ignition_led = None
    buzzer = None

# ... (Utils & Beacon Helpers are unchanged) ...
def path_to_mac(path: str) -> str:
    try: return path.split("/")[-1].replace("dev_", "").replace("_", ":")
    except Exception: return str(path)
def load_trusted_device():
    try:
        with open(TRUSTED_DEVICE_FILE, "r") as f: return json.load(f).get("device_id")
    except Exception: return None
def save_trusted_device(device_id):
    try:
        with open(TRUSTED_DEVICE_FILE, "w") as f: json.dump({"device_id": device_id}, f)
    except Exception as e: print(f"⚠️ Failed to save trusted device: {e}")
last_trusted_mac = load_trusted_device()
def rolling_token(window=TOKEN_WINDOW, trunc_bytes=TOKEN_TRUNC_BYTES):
    bucket = int(time.time()) // window
    hm = hmac.new(SHARED_SECRET, str(bucket).encode(), hashlib.sha256).digest()
    return int.from_bytes(hm[:trunc_bytes], byteorder='big')
def get_pi_major_from_mac():
    try:
        mac = subprocess.check_output("hciconfig | grep 'BD Address'", shell=True).decode()
        mac_addr = mac.split()[2]
        parts = mac_addr.split(":")
        return (int(parts[-2], 16) << 8) | int(parts[-1], 16)
    except Exception as e:
        print(f"⚠️ Could not get MAC, fallback major=1: {e}")
        return 1
def build_ibeacon_payload():
    uuid_bytes = bytes.fromhex(BEACON_UUID.replace("-", ""))
    major = get_pi_major_from_mac()
    minor = rolling_token()
    payload = struct.pack(">H16sHHb", 0x0215, uuid_bytes, major, minor, TX_POWER)
    return list(payload)

# ... (Advertisements, GATT Chars, BT Service & App are unchanged until trigger_alarm) ...
class GattAdvertisement(Advertisement):
    def __init__(self, bus, index):
        super().__init__(bus, index, "peripheral")
        self.add_service_uuid("1234"); self.add_local_name(LOCAL_NAME[:8]); self.include_tx_power = True
class IBeaconAdvertisement(Advertisement):
    def __init__(self, bus, index):
        super().__init__(bus, index, "broadcast")
        self.add_manufacturer_data(IBEACON_COMPANY_ID, build_ibeacon_payload())
class TokenCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        super().__init__(bus, index, TOKEN_CHAR_UUID, ["write"], service)
    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        global token_verified, authorized_device_path, last_trusted_mac
        device = options.get("device"); token = bytes(value).decode("utf-8", errors="ignore").strip()
        dev_mac = path_to_mac(device); print(f"🔑 Token received from {dev_mac}: {token}")
        totp = pyotp.TOTP(TOTP_SECRET)
        if totp.verify(token):
            print("✅ Valid TOTP. Access granted.")
            token_verified = True; authorized_device_path = device
            last_trusted_mac = dev_mac; save_trusted_device(dev_mac); clear_alarm()
        else:
            print("⛔ Invalid TOTP. Triggering alarm.")
            token_verified = False; trigger_alarm()
class SecureCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        super().__init__(bus, index, DATA_CHAR_UUID, ["read", "write"], service)
        self.value = dbus.Array([], signature='y')
    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        if alarm_active: raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Alarm active")
        if not token_verified or options.get("device") != authorized_device_path:
            trigger_alarm(); raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Unauthorized")
        return self.value
    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        if alarm_active: raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Alarm active")
        if not token_verified or options.get("device") != authorized_device_path:
            trigger_alarm(); raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Unauthorized")
        self.value = value; self.PropertiesChanged("org.bluez.GattCharacteristic1", {"Value": self.value}, [])
class ControlCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        super().__init__(bus, index, CONTROL_CHAR_UUID, ["write"], service)
    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        if alarm_active: raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Alarm active")
        device, payload = options.get("device"), bytes(value).decode("utf-8", errors="ignore").strip().lower()
        if not token_verified or device != authorized_device_path:
            trigger_alarm(); raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Unauthorized")
        if payload == "clear": clear_alarm()
class BluetoothService(Service):
    def __init__(self, bus, index):
        super().__init__(bus, index, SERVICE_UUID, True)
        self.add_characteristic(TokenCharacteristic(bus, 0, self))
        self.add_characteristic(SecureCharacteristic(bus, 1, self))
        self.add_characteristic(ControlCharacteristic(bus, 2, self))
class BluetoothApplication:
    def __init__(self):
        global bus
        self.bus, self.app = dbus.SystemBus(), Application(dbus.SystemBus())
        bus = self.bus; self.adapter_path = self._find_adapter()
        if not self.adapter_path: raise RuntimeError("BLE adapter not found")
        self.ad_manager = dbus.Interface(bus.get_object("org.bluez", self.adapter_path), "org.bluez.LEAdvertisingManager1")
        self.service_manager = dbus.Interface(bus.get_object("org.bluez", self.adapter_path), "org.bluez.GattManager1")
        try: self.gatt_adv = GattAdvertisement(bus, 0)
        except Exception as e: print(f"⚠️ GATT advert create error: {e}"); self.gatt_adv = None
        try: self.ibeacon_adv = IBeaconAdvertisement(bus, 1)
        except Exception as e: print(f"⚠️ iBeacon advert create error: {e}"); self.ibeacon_adv = None
    def _find_adapter(self):
        om = dbus.Interface(bus.get_object("org.bluez", "/"), "org.freedesktop.DBus.ObjectManager")
        for path, props in om.GetManagedObjects().items():
            if "org.bluez.LEAdvertisingManager1" in props: return path
        return None
    def _register_advert(self, adv_obj):
        global current_adv
        self._unregister_advert(); current_adv = adv_obj
        try: self.ad_manager.RegisterAdvertisement(current_adv.get_path(), {}, reply_handler=lambda: print("✅ Ad registered"), error_handler=lambda e: print(f"❌ Ad register error: {e}"))
        except Exception as e: print(f"⚠️ RegisterAd exception: {e}")
    def _unregister_advert(self):
        global current_adv, adv_refresh_id
        if current_adv:
            try: self.ad_manager.UnregisterAdvertisement(current_adv.get_path())
            except Exception: pass
            current_adv = None
        if adv_refresh_id:
            try: GLib.source_remove(adv_refresh_id)
            except Exception: pass
            adv_refresh_id = None
    def start_gatt_advert(self):
        if not self.gatt_adv: return
        print("➡️ Starting GATT ad (normal mode)"); self._register_advert(self.gatt_adv)
        global adv_refresh_id
        if adv_refresh_id: GLib.source_remove(adv_refresh_id)
        adv_refresh_id = GLib.timeout_add_seconds(TOKEN_WINDOW, lambda: True)
    def start_ibeacon_advert(self):
        if not self.ibeacon_adv: return
        print("➡️ Starting iBeacon ad (alarm mode)"); self._register_advert(self.ibeacon_adv)
        def refresh_ibeacon():
            current_adv.add_manufacturer_data(IBEACON_COMPANY_ID, build_ibeacon_payload()); return True
        global adv_refresh_id
        if adv_refresh_id: GLib.source_remove(adv_refresh_id)
        adv_refresh_id = GLib.timeout_add_seconds(TOKEN_WINDOW, refresh_ibeacon)
    def run(self):
        global ignition_characteristic_obj
        self.app.add_service(BluetoothService(bus, 0))
        try: 
            two_wheeler_service = TwoWheelerService(bus, 1, ignition_led=ignition_led)
            self.app.add_service(two_wheeler_service)
            for char in two_wheeler_service.get_characteristics():
                if char.char_id == TwoWheelerCharID.IGNITION_STATE:
                    ignition_characteristic_obj = char
                    print("✅ Found ignition characteristic object.")
                    break
        except Exception as e: print(f"Error setting up TwoWheelerService: {e}"); pass
        self.service_manager.RegisterApplication(self.app.get_path(), {}, reply_handler=lambda: (print("✅ GATT app registered"), self.start_gatt_advert()), error_handler=lambda e: (print(f"❌ App register error: {e}"), sys.exit(1)))
        GLib.MainLoop().run()
    def cleanup(self):
        self._unregister_advert()
        try: self.service_manager.UnregisterApplication(self.app.get_path())
        except Exception: pass

# -----------------------------
# Alarm & Push Button Logic
# -----------------------------
def trigger_alarm():
    global alarm_active
    if alarm_active: return
    alarm_active = True
    print("🚨 Alarm triggered! Switching to iBeacon mode.")
    if ignition_led:
        try:
            ignition_led.on()
            GLib.timeout_add_seconds(3, lambda *_: ignition_led.off() or False)
        except Exception as e:
            print(f"⚠️ Could not activate ignition LED for alarm: {e}")
    
    if buzzer:
        try:
            # v-- MODIFIED BUZZER LOGIC --v
            # Blink for ~3 seconds (e.g., 8 cycles of 0.2s on/off)
            buzzer.blink(on_time=0.2, off_time=0.2, n=8, background=True)
            # ^-- END MODIFICATION --^
        except Exception as e:
            print(f"⚠️ Could not activate buzzer for alarm: {e}")

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
    
def handle_button_press():
    if not token_verified:
        print("🔵 PUSH BUTTON: Owner not authenticated. Sounding warning buzzer.")
        if buzzer:
            try:
                # v-- MODIFIED BUZZER LOGIC --v
                # Blink for ~3 seconds
                buzzer.blink(on_time=0.2, off_time=0.2, n=8, background=True)
                # ^-- END MODIFICATION --^
            except Exception as e:
                print(f"⚠️ Could not activate buzzer: {e}")
        return

    if not ignition_characteristic_obj:
        print("⚠️ PUSH BUTTON: Characteristic object not found. Cannot update state.")
        return
        
    current_state = char_values[TwoWheelerCharID.IGNITION_STATE]
    new_state = not current_state
    print(f"🟢 PUSH BUTTON: Requesting ignition change to {'ON' if new_state else 'OFF'}")
    ignition_characteristic_obj.update_and_notify_state(new_state)

# ... (Connection Handling, Discovery, and Main function are unchanged) ...
def ensure_bonding(path, mac):
    try:
        dev = bus.get_object("org.bluez", path)
        props = dbus.Interface(dev, "org.freedesktop.DBus.Properties")
        if not bool(props.Get("org.bluez.Device1", "Paired")):
            dbus.Interface(dev, "org.bluez.Device1").Pair()
    except Exception as e: print(f"⚠️ Bonding check failed: {e}")
def handle_trusted_reconnect(mac, path, props):
    global token_verified, authorized_device_path, auto_reconnect_id, connecting_attempt
    if mac != last_trusted_mac: return
    print(f"✅ Owner {mac} reconnected.")
    token_verified, authorized_device_path, connecting_attempt = True, path, False
    app.start_gatt_advert(); stop_discovery()
    if auto_reconnect_id:
        try: GLib.source_remove(auto_reconnect_id)
        except Exception: pass
        auto_reconnect_id = None
def handle_disconnect(mac, path):
    global token_verified, authorized_device_path, auto_reconnect_id
    if mac == last_trusted_mac and token_verified:
        print(f"ℹ️ Owner {mac} disconnected → starting auto-reconnect")
        token_verified, authorized_device_path = False, None
        if auto_reconnect_id is None:
            start_discovery()
            auto_reconnect_id = GLib.timeout_add_seconds(10, attempt_autoconnect)
def properties_changed_handler(interface, changed, invalidated, path=None):
    if interface != "org.bluez.Device1": return
    mac = path_to_mac(path)
    if "Connected" in changed:
        if changed["Connected"]:
            ensure_bonding(path, mac)
            if mac == last_trusted_mac: handle_trusted_reconnect(mac, path, None)
            else:
                trigger_alarm()
                try: dbus.Interface(bus.get_object("org.bluez", path), "org.bluez.Device1").Disconnect()
                except Exception as e: print(f"⚠️ Could not disconnect {mac}: {e}")
        else: handle_disconnect(mac, path)
def interfaces_removed_handler(path, interfaces):
    if "org.bluez.Device1" in interfaces: handle_disconnect(path_to_mac(path), path)
def start_discovery():
    global discovery_active
    if discovery_active: return
    try:
        adapter = bus.get_object("org.bluez", app.adapter_path)
        dbus.Interface(adapter, "org.bluez.Adapter1").StartDiscovery()
        print("🔎 Discovery started"); discovery_active = True
    except Exception: pass
def stop_discovery():
    global discovery_active
    if not discovery_active: return
    try:
        adapter = bus.get_object("org.bluez", app.adapter_path)
        dbus.Interface(adapter, "org.bluez.Adapter1").StopDiscovery()
        print("🛑 Discovery stopped"); discovery_active = False
    except Exception: pass
def clear_connecting_flag():
    global connecting_attempt
    connecting_attempt = False; return False
def attempt_autoconnect():
    global last_trusted_mac, last_connect_attempt, auto_reconnect_id, connecting_attempt
    if not last_trusted_mac:
        auto_reconnect_id = None; return False
    if connecting_attempt or (time.time() - last_connect_attempt < CONNECT_COOLDOWN):
        return True
    om = dbus.Interface(bus.get_object("org.bluez", "/"), "org.freedesktop.DBus.ObjectManager")
    managed = om.GetManagedObjects()
    target_path, props_iface = None, None
    for path, ifaces in managed.items():
        if "org.bluez.Device1" in ifaces and ifaces["org.bluez.Device1"].get("Address", "").upper() == last_trusted_mac.upper():
            target_path, props_iface = path, ifaces["org.bluez.Device1"]; break
    if not target_path:
        print(f"🔍 Trusted device {last_trusted_mac} not found, continuing scan..."); return True
    if props_iface.get("Connected", False):
        print("✅ Device found connected. Stopping reconnect timer.")
        auto_reconnect_id = None; return False
    if not props_iface.get("Paired", False):
        print(f"⚠️ Trusted device {last_trusted_mac} no longer paired. Cannot reconnect.")
        auto_reconnect_id = None; return False
    try:
        print(f"📱 Attempting auto-reconnect to {last_trusted_mac}...")
        connecting_attempt = True
        dbus.Interface(bus.get_object("org.bluez", target_path), "org.bluez.Device1").Connect()
        last_connect_attempt = time.time()
        GLib.timeout_add_seconds(CONNECT_COOLDOWN, clear_connecting_flag)
    except Exception: connecting_attempt = False
    return True
def reset_button_callback(channel):
    global alarm_active
    if not alarm_active:
        print("🔘 Reset button pressed, no alarm active → ignored"); return
    print("🔘 Reset button pressed → enabling connectable window for auth")
    app.start_gatt_advert()
    GLib.timeout_add_seconds(15, lambda *_: revert_to_beacon_if_alarm() or False)
def revert_to_beacon_if_alarm():
    global alarm_active
    if alarm_active:
        print("⏳ Connectable window expired → reverting to beacon mode")
        app.start_ibeacon_advert()
if __name__ == "__main__":
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    agent = NoInputNoOutputAgent(bus)
    mgr = dbus.Interface(bus.get_object("org.bluez", "/org/bluez"), "org.bluez.AgentManager1")
    try:
        mgr.RegisterAgent("/test/agent", "NoInputNoOutput")
        mgr.RequestDefaultAgent("/test/agent")
        print("🔑 Agent registered & set as default")
    except Exception as e:
        print(f"⚠️ Could not register agent: {e}")
    subprocess.run(["bluetoothctl", "discoverable", "on"], check=False)
    subprocess.run(["bluetoothctl", "pairable", "on"], check=False)
    if factory:
        try:
            button = Button(PUSH_BUTTON_PIN, pull_up=True, bounce_time=0.3, pin_factory=factory)
            button.when_pressed = handle_button_press
            print(f"🔘 Push button handler registered on GPIO {PUSH_BUTTON_PIN} using pigpio factory.")
            reset_button = Button(RESET_PIN, pull_up=True, bounce_time=0.3, pin_factory=factory)
            reset_button.when_pressed = reset_button_callback
            print(f"🔘 Reset button handler registered on GPIO {RESET_PIN} using pigpio factory.")
        except Exception as e:
            print(f"⚠️ Could not register button handler with pigpio: {e}")
    bus.add_signal_receiver(properties_changed_handler, dbus_interface="org.freedesktop.DBus.Properties", signal_name="PropertiesChanged", path_keyword="path")
    bus.add_signal_receiver(interfaces_removed_handler, dbus_interface="org.freedesktop.DBus.ObjectManager", signal_name="InterfacesRemoved")
    print("🔎 DBus signal receivers registered")
    app = BluetoothApplication()
    try:
        app.run()
    except KeyboardInterrupt:
        app.cleanup()
        print("\n✨ Exiting gracefully.")
        sys.exit(0)