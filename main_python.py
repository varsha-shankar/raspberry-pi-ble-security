#!/usr/bin/env python3
# main_python.py — BLE anti-theft system with owner/stranger logic
# NOTE: TOTP removed. Mutual HMAC auth implemented in TokenCharacteristic.
#       Session key can be persisted to disk (encrypted with factory key).

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
import os
import secrets
from Crypto.Cipher import AES

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
# TOTP removed (no pyotp, no TOTP_SECRET)

SERVICE_UUID      = "00001234-0000-1000-8000-00805f9b34fb"
TOKEN_CHAR_UUID   = "0000abcd-0000-1000-8000-00805f9b34fb"
DATA_CHAR_UUID    = "00005678-0000-1000-8000-00805f9b34fb"
CONTROL_CHAR_UUID = "0000c0de-0000-1000-8000-00805f9b34fb"

IBEACON_COMPANY_ID = 0x004C
BEACON_UUID = SERVICE_UUID
SHARED_SECRET = b"super_secret_key"   # Factory key K0 placeholder; load_or_create_secret_key() will replace if file used
TOKEN_WINDOW = 30
TOKEN_TRUNC_BYTES = 2
TX_POWER = -59

RESET_PIN = 24

# --- Secure HMAC Auth ---
SESSION_KEY = None
SESSION_NONCE_TCU = None
SESSION_NONCE_APP = None
HMAC_SECRET_FILE = "bike_secret.bin"
SESSION_FILE = "session_key.bin"   # optional persisted session key (encrypted)

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

# -----------------------------
# Utils & Beacon Helpers
# -----------------------------
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

# Rolling token is used only for iBeacon minor rotation (no TOTP dependency)
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

def load_or_create_secret_key():
    """
    Load K0 from disk or create if missing.
    This is the factory secret used for HMACs and encrypting session file.
    """
    global SHARED_SECRET
    if not os.path.exists(HMAC_SECRET_FILE):
        key = secrets.token_bytes(32)
        with open(HMAC_SECRET_FILE, "wb") as f:
            f.write(key)
        os.chmod(HMAC_SECRET_FILE, 0o600)
        print("🔐 New factory HMAC key generated")
    else:
        with open(HMAC_SECRET_FILE, "rb") as f:
            key = f.read()
    SHARED_SECRET = key
    return key

def derive_session_key(base_key, nonce_app, nonce_tcu):
    """Derive per-session key: HMAC(K0, N_app || N_tcu)."""
    msg = nonce_app + nonce_tcu
    return hmac.new(base_key, msg, hashlib.sha256).digest()

# Session persistence helpers (encrypt session key with factory K0)
def store_session_key(session_key: bytes):
    try:
        # AES-GCM with K0 as key (use first 32 bytes of K0)
        aes_key = hashlib.sha256(SHARED_SECRET).digest()  # 32 bytes
        iv = secrets.token_bytes(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(session_key)
        with open(SESSION_FILE, "wb") as f:
            f.write(iv + tag + ciphertext)
        os.chmod(SESSION_FILE, 0o600)
        print("🔒 Session key persisted to disk.")
    except Exception as e:
        print(f"⚠️ Failed to store session key: {e}")

def load_session_key():
    global SESSION_KEY
    try:
        if not os.path.exists(SESSION_FILE):
            return None
        aes_key = hashlib.sha256(SHARED_SECRET).digest()
        data = open(SESSION_FILE, "rb").read()
        iv = data[:12]; tag = data[12:28]; ciphertext = data[28:]
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        sk = cipher.decrypt_and_verify(ciphertext, tag)
        SESSION_KEY = sk
        print("🔓 Loaded persisted session key from disk.")
        return sk
    except Exception as e:
        print(f"⚠️ Failed to load session key: {e}")
        return None

def clear_session_file():
    try:
        if os.path.exists(SESSION_FILE):
            os.remove(SESSION_FILE)
            print("🗑️ Session file removed.")
    except Exception as e:
        print(f"⚠️ Could not remove session file: {e}")

# -----------------------------
# Advertisements
# -----------------------------
class GattAdvertisement(Advertisement):
    def __init__(self, bus, index):
        super().__init__(bus, index, "peripheral")
        self.add_service_uuid("1234"); self.add_local_name(LOCAL_NAME[:8]); self.include_tx_power = True

class IBeaconAdvertisement(Advertisement):
    def __init__(self, bus, index):
        super().__init__(bus, index, "broadcast")
        payload = build_ibeacon_payload()
        self.add_manufacturer_data(IBEACON_COMPANY_ID, payload)

# -----------------------------
# GATT Characteristics
# -----------------------------
class TokenCharacteristic(Characteristic):
    """
    HMAC mutual-auth with the trusted device.
    Flow:
      1) App writes {"nonce_app": "<hex>"}  -> Pi responds with {"nonce_tcu": "<hex>"} (notify)
      2) App writes {"hmac_app": "<hex>"}  -> Pi verifies HMAC and responds {"hmac_tcu": "<hex>"}
    This characteristic only accepts auth attempts from the stored last_trusted_mac.
    """
    def __init__(self, bus, index, service):
        super().__init__(bus, index, TOKEN_CHAR_UUID, ["write", "notify"], service)
        self.value = dbus.Array([], signature='y')
        self.add_descriptor("2901", "Token Exchange for Mutual Auth")

    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        global token_verified, authorized_device_path, last_trusted_mac
        global SESSION_KEY, SESSION_NONCE_TCU, SESSION_NONCE_APP

        device = options.get("device")
        dev_mac = path_to_mac(device)
        payload = bytes(value)
        print(f"🔑 TokenCharacteristic.WriteValue() from {dev_mac}: {payload[:80]!r}")

        # If we have a known trusted device, only accept writes from it for auth
        if last_trusted_mac and dev_mac.upper() != last_trusted_mac.upper():
            print(f"⛔ Auth attempt from untrusted device {dev_mac} (expected {last_trusted_mac})")
            # raise alarm and disconnect
            trigger_alarm()
            try:
                dbus.Interface(bus.get_object("org.bluez", device), "org.bluez.Device1").Disconnect()
            except Exception:
                pass
            return

        # Parse JSON payload (two-stage exchange)
        try:
            data = json.loads(payload.decode())
        except Exception:
            print("⚠️ Invalid JSON payload for auth.")
            return

        # Stage 1: App sends nonce_app to start auth
        if "nonce_app" in data and not SESSION_NONCE_TCU:
            try:
                SESSION_NONCE_APP = bytes.fromhex(data["nonce_app"])
            except Exception:
                print("⚠️ Invalid nonce_app hex")
                return
            SESSION_NONCE_TCU = secrets.token_bytes(16)
            # Notify back nonce_tcu
            resp = json.dumps({"nonce_tcu": SESSION_NONCE_TCU.hex()})
            self.PropertiesChanged("org.bluez.GattCharacteristic1", {"Value": [dbus.Byte(c) for c in resp.encode()]}, [])
            print("↩️ Sent TCU nonce to app.")
            return

        # Stage 2: App sends hmac_app to complete auth
        if "hmac_app" in data and SESSION_NONCE_APP and SESSION_NONCE_TCU:
            try:
                hmac_app = bytes.fromhex(data["hmac_app"])
            except Exception:
                print("⚠️ Invalid hmac_app hex")
                return

            # Expected HMAC = HMAC(K0, nonce_tcu || nonce_app)
            expected = hmac.new(SHARED_SECRET, SESSION_NONCE_TCU + SESSION_NONCE_APP, hashlib.sha256).digest()
            if hmac.compare_digest(hmac_app, expected):
                # Verified: derive session key and mark verified
                print("✅ HMAC verified! Generating session key.")
                SESSION_KEY = derive_session_key(SHARED_SECRET, SESSION_NONCE_APP, SESSION_NONCE_TCU)
                token_verified = True
                authorized_device_path = device
                last_trusted_mac = dev_mac
                save_trusted_device(dev_mac)
                clear_alarm()

                # Persist session key to disk (optional)
                try:
                    store_session_key(SESSION_KEY)
                except Exception:
                    pass

                # Respond with our HMAC to complete mutual auth: HMAC(K0, nonce_app || nonce_tcu)
                hmac_tcu = hmac.new(SHARED_SECRET, SESSION_NONCE_APP + SESSION_NONCE_TCU, hashlib.sha256).digest()
                resp = json.dumps({"hmac_tcu": hmac_tcu.hex()})
                self.PropertiesChanged("org.bluez.GattCharacteristic1", {"Value": [dbus.Byte(c) for c in resp.encode()]}, [])
                print("🔄 Mutual auth complete, session key established.")
            else:
                print("⛔ Invalid HMAC, triggering alarm.")
                token_verified = False
                # zero volatile state
                SESSION_KEY = None
                SESSION_NONCE_APP = None
                SESSION_NONCE_TCU = None
                clear_session_file()
                trigger_alarm()
            return

        print("⚠️ Unhandled TokenCharacteristic payload.")

class SecureCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        super().__init__(bus, index, DATA_CHAR_UUID, ["read", "write"], service)
        self.value = dbus.Array([], signature='y')

    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        if alarm_active:
            print("⛔ Alarm active → denying read")
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Alarm active")
        if not token_verified or options.get("device") != authorized_device_path:
            print("⛔ Unauthorized read attempt")
            trigger_alarm()
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Unauthorized")

        # If a session key exists, encrypt sample data using AES-GCM
        plaintext = b"secure-data"
        if SESSION_KEY:
            try:
                iv = os.urandom(12)
                cipher = AES.new(SESSION_KEY[:32], AES.MODE_GCM, nonce=iv)
                ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                blob = iv + tag + ciphertext
                return dbus.Array([dbus.Byte(b) for b in blob], signature='y')
            except Exception as e:
                print(f"⚠️ Encryption error: {e}")
                raise dbus.exceptions.DBusException("org.bluez.Error.Failed", "Encryption failed")
        else:
            # no session key -> return plaintext (or you may choose to reject)
            return dbus.Array([dbus.Byte(b) for b in plaintext], signature='y')

    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        if alarm_active:
            print("⛔ Alarm active → denying write")
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Alarm active")
        if not token_verified or options.get("device") != authorized_device_path:
            print("⛔ Unauthorized write attempt")
            trigger_alarm()
            raise dbus.exceptions.DBusException("org.bluez.Error.NotAuthorized", "Unauthorized")

        # Attempt decrypt if session key present
        data = bytes(value)
        if SESSION_KEY:
            try:
                iv, tag, ciphertext = data[:12], data[12:28], data[28:]
                cipher = AES.new(SESSION_KEY[:32], AES.MODE_GCM, nonce=iv)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                print(f"🧾 Received secure data (decrypted): {plaintext}")
                self.value = dbus.Array([dbus.Byte(b) for b in plaintext], signature='y')
                self.PropertiesChanged("org.bluez.GattCharacteristic1", {"Value": self.value}, [])
            except Exception as e:
                print(f"⚠️ Decryption error: {e}")
                raise dbus.exceptions.DBusException("org.bluez.Error.Failed", "Decryption failed")
        else:
            # accept raw write when no session key (legacy)
            self.value = dbus.Array([dbus.Byte(b) for b in data], signature='y')
            print("✅ Authorized write (raw):", list(data))
            self.PropertiesChanged("org.bluez.GattCharacteristic1", {"Value": self.value}, [])

class ControlCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        super().__init__(bus, index, CONTROL_CHAR_UUID, ["write"], service)

    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        if alarm_active:
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

        # create and keep advertisement objects so they are not re-added repeatedly
        try:
            self.gatt_adv = GattAdvertisement(self.bus, 0)
        except Exception as e:
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
        try:
            if current_adv and hasattr(current_adv, "get_path") and hasattr(adv_obj, "get_path"):
                if current_adv.get_path() == adv_obj.get_path():
                    print("➡️ Advertisement already active — skipping register")
                    return
        except Exception:
            pass

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
            current_adv = None
        if adv_refresh_id:
            try: GLib.source_remove(adv_refresh_id)
            except Exception: pass
            adv_refresh_id = None

    def start_gatt_advert(self):
        if not self.gatt_adv:
            try:
                self.gatt_adv = GattAdvertisement(self.bus, 0)
            except Exception as e:
                print(f"⚠️ Failed to create GATT advert on demand: {e}")
                return

        print("➡️ Starting connectable GATT advertisement (normal mode)")
        self._register_advert(self.gatt_adv)

        def refresh_gatt_token():
            # keep advertisement minimal
            return True

        global adv_refresh_id
        if adv_refresh_id:
            try: GLib.source_remove(adv_refresh_id)
            except Exception: pass
        adv_refresh_id = GLib.timeout_add_seconds(TOKEN_WINDOW, refresh_gatt_token)

    def start_ibeacon_advert(self):
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
                current_adv.add_manufacturer_data(IBEACON_COMPANY_ID, payload)
                uuid = ''.join(f'{b:02X}' for b in payload[2:18])
                major = (payload[18] << 8) | payload[19]
                minor = (payload[20] << 8) | payload[21]
                tx_power = payload[22] - 256 if payload[22] > 127 else payload[22]
                print(f"UUID={uuid}, Major={major}, Minor={minor}, TX Power={tx_power}")
            except Exception as e:
                print(f"⚠️ Failed to refresh iBeacon payload: {e}")
            return True

        global adv_refresh_id
        if adv_refresh_id:
            try: GLib.source_remove(adv_refresh_id)
            except Exception: pass
        adv_refresh_id = GLib.timeout_add_seconds(TOKEN_WINDOW, refresh_ibeacon)

    def run(self):
        service = BluetoothService(self.bus, 0)
        self.app.add_service(service)
        try:
            two_wheeler = TwoWheelerService(self.bus, 1, ignition_led=ignition_led)
            self.app.add_service(two_wheeler)
            for char in two_wheeler.get_characteristics():
                if char.char_id == TwoWheelerCharID.IGNITION_STATE:
                    global ignition_characteristic_obj
                    ignition_characteristic_obj = char
                    print("✅ Found ignition characteristic object.")
                    break
        except Exception as e:
            print(f"Error setting up TwoWheelerService: {e}"); pass

        self.service_manager.RegisterApplication(self.app.get_path(), {},
            reply_handler=lambda: (print("✅ GATT app registered"), self.start_gatt_advert()),
            error_handler=lambda e: (print(f"❌ App register error: {e}"), sys.exit(1)))

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
            # Blink for ~3 seconds (e.g., 8 cycles of 0.2s on/off)
            buzzer.blink(on_time=0.2, off_time=0.2, n=8, background=True)
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
                buzzer.blink(on_time=0.2, off_time=0.2, n=8, background=True)
            except Exception as e:
                print(f"⚠️ Could not activate buzzer for alarm: {e}")
        return

    if not ignition_characteristic_obj:
        print("⚠️ PUSH BUTTON: Characteristic object not found. Cannot update state.")
        return
        
    current_state = char_values[TwoWheelerCharID.IGNITION_STATE]
    new_state = not current_state
    print(f"🟢 PUSH BUTTON: Requesting ignition change to {'ON' if new_state else 'OFF'}")
    ignition_characteristic_obj.update_and_notify_state(new_state)

# -----------------------------
# Connection Handling
# -----------------------------
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

# -----------------------------
# Discovery helpers
# -----------------------------
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

def reset_button_callback(channel=None):
    # Clear session (Ks) and allow a connectable window for owner to re-authenticate
    global alarm_active, SESSION_KEY, SESSION_NONCE_APP, SESSION_NONCE_TCU, token_verified, authorized_device_path, last_trusted_mac
    if not alarm_active:
        print("🔘 Reset button pressed, no alarm active → ignored"); return
    print("🔘 Reset button pressed → enabling connectable window for auth and clearing session")
    # Clear volatile session/state
    SESSION_KEY = None
    SESSION_NONCE_APP = None
    SESSION_NONCE_TCU = None
    token_verified = False
    authorized_device_path = None
    # Remove persisted session (so we won't auto-restore)
    clear_session_file()
    # Allow connectable GATT advertising for short window
    try:
        app.start_gatt_advert()
    except Exception:
        pass
    GLib.timeout_add_seconds(15, lambda *_: revert_to_beacon_if_alarm() or False)

def revert_to_beacon_if_alarm():
    global alarm_active
    if alarm_active:
        print("⏳ Connectable window expired → reverting to beacon mode")
        app.start_ibeacon_advert()

# -----------------------------
# Secret Key Setup
# -----------------------------
SHARED_SECRET = load_or_create_secret_key()
# Try load persisted session key if present
load_session_key()

# -----------------------------
# Main Entry Point
# -----------------------------
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
