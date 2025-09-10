#!/usr/bin/env python3
"""
twist_tcu.py
Two-Wheeler Intrusion & Security TCU (Raspberry Pi)
- State machine: PAIRED_SAFE -> ARMED_MONITOR -> DISTRESS
- Beacon re-registration for controlled frequency (armed / distress)
- MPU-6050 accelerometer reading (I2C) for intrusion detection
- GPIO control for siren (relay)
- Integrates with BLE advertising + GATT modules (advertisement.py, service.py, agent.py)
"""

import time
import threading
import json
import os
import signal
import sys
import traceback
from datetime import datetime

# DBus / BlueZ
import dbus
import dbus.mainloop.glib
from gi.repository import GLib

# I2C & GPIO
from smbus2 import SMBus
import RPi.GPIO as GPIO

# Import your existing BLE helpers (expected in same folder)
# advertisement.py must provide Advertisement base class
# service.py must provide Application, Service, Characteristic classes
# agent.py must provide NoInputNoOutputAgent
from advertisement import Advertisement
from service import Application, Service, Characteristic
from agent import NoInputNoOutputAgent

# ------------------------
# Configuration
# ------------------------
# BLE / Beacon
TWIST_UUID = "f0000000-0000-1000-8000-00805f9b34fb"  # example 128-bit UUID (replace)
TWIST_MAJOR = 1234
MINOR_ARMED = 1
MINOR_DISTRESS = 911

# Beacon timings (seconds)
ARMED_BEACON_INTERVAL = 5.0        # beacon every 5s while armed
DISTRESS_BEACON_INTERVAL = 0.5     # beacon every 0.5s when intruded

# Owner pairing timeout (seconds): after owner disconnect, wait this then arm
ARM_DELAY_AFTER_OWNER_LEAVES = 10.0

# MPU-6050 (I2C)
I2C_BUS = 1         # typical on Raspberry Pi
MPU6050_ADDR = 0x68
ACCEL_THRESHOLD = 1.6   # g units; tune as required
DEBOUNCE_MS = 300       # ms that accel must remain above threshold

# GPIO pins
SIREN_PIN = 17         # BCM pin to drive relay for siren
LED_PIN = 27           # optional status LED

# Logging & persistence
LOG_FILE = "/var/log/twist_tcu_events.log"   # ensure process has permissions or change to local path

# ------------------------
# Globals / state
# ------------------------
bus = None               # DBus system bus, set in main
app = None               # BluetoothApplication instance (created later)
stop_event = threading.Event()

state_lock = threading.Lock()
STATE_PAIRED_SAFE = "PAIRED_SAFE"
STATE_ARMED_MONITOR = "ARMED_MONITOR"
STATE_DISTRESS = "DISTRESS"

state = STATE_PAIRED_SAFE
owner_connected = False   # updated by DBus PropertiesChanged handler
last_owner_disconnect_time = None

# authorized device path (set when owner pairs / token verified)
authorized_device_path = None

# BLE ad index to create unique object paths
ad_index = 0

# ------------------------
# Helper utilities
# ------------------------
def log_event(data: dict):
    """Append event (with timestamp) to local log file."""
    data["timestamp"] = datetime.utcnow().isoformat() + "Z"
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    except Exception:
        pass
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data) + "\n")
    except Exception as e:
        print("Failed to write log:", e)

def path_to_mac(path: str) -> str:
    return path.split("/")[-1].replace("dev_", "").replace("_", ":")

# ------------------------
# GPIO (siren) helpers
# ------------------------
def gpio_setup():
    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(SIREN_PIN, GPIO.OUT, initial=GPIO.LOW)
    GPIO.setup(LED_PIN, GPIO.OUT, initial=GPIO.LOW)

def sound_siren(duration_s=10):
    try:
        print(f"[SIREN] Activating siren for {duration_s}s")
        GPIO.output(SIREN_PIN, GPIO.HIGH)
        time.sleep(duration_s)
    finally:
        GPIO.output(SIREN_PIN, GPIO.LOW)

def set_led(on: bool):
    GPIO.output(LED_PIN, GPIO.HIGH if on else GPIO.LOW)

# ------------------------
# MPU-6050 minimal driver
# ------------------------
class MPU6050:
    # Registers
    PWR_MGMT_1 = 0x6B
    ACCEL_XOUT_H = 0x3B
    ACCEL_CONFIG = 0x1C
    GYRO_CONFIG = 0x1B

    def __init__(self, i2c_bus=I2C_BUS, addr=MPU6050_ADDR):
        self.bus = SMBus(i2c_bus)
        self.addr = addr
        # Wake up the sensor
        self.bus.write_byte_data(self.addr, self.PWR_MGMT_1, 0x00)
        # set accelerometer range to ±2g (0)
        self.bus.write_byte_data(self.addr, self.ACCEL_CONFIG, 0x00)
        # set gyro range ±250deg/s
        self.bus.write_byte_data(self.addr, self.GYRO_CONFIG, 0x00)
        time.sleep(0.1)

    def read_raw_accel(self):
        data = self.bus.read_i2c_block_data(self.addr, self.ACCEL_XOUT_H, 6)
        def to_signed(h, l):
            val = (h << 8) | l
            if val >= 0x8000:
                val = -((65535) - val + 1)
            return val
        ax = to_signed(data[0], data[1])
        ay = to_signed(data[2], data[3])
        az = to_signed(data[4], data[5])
        return ax, ay, az

    def read_accel_g(self):
        ax, ay, az = self.read_raw_accel()
        # sensitivity for ±2g is 16384 LSB/g
        return ax / 16384.0, ay / 16384.0, az / 16384.0

# ------------------------
# BLE Advertisement wrapper (relies on advertisement.py)
# ------------------------
class TwistAdvertisement(Advertisement):
    def __init__(self, bus, index, minor):
        super().__init__(bus, index, "peripheral")
        # set service UUID and short payload data in service_data or manufacturer data
        # We'll use service UUID and put Major/Minor in ServiceData bytes
        # ServiceData: [majorHigh, majorLow, minorHigh, minorLow]
        self.add_service_uuid(TWIST_UUID)
        self.set_service_data(TWIST_UUID, [
            (TWIST_MAJOR >> 8) & 0xFF, TWIST_MAJOR & 0xFF,
            (minor >> 8) & 0xFF, minor & 0xFF
        ])
        self.add_local_name("TWIST-TCU")
        self.include_tx_power = True

    # helper if Advertisement base uses different property names; adapt if needed
    def set_service_data(self, uuid, byte_list):
        # Some advertisement.py implementations use self.service_data dict
        try:
            self.service_data = {uuid: dbus.Array(bytearray(byte_list), signature='y')}
        except Exception:
            # fallback: set attribute
            self.service_data = {uuid: bytearray(byte_list)}

# ------------------------
# BLE Application wrapper (minimal advertisement control)
# ------------------------
class BeaconController:
    def __init__(self, system_bus, adapter_path):
        self.bus = system_bus
        self.adapter = adapter_path
        self.ad_manager = dbus.Interface(self.bus.get_object("org.bluez", self.adapter),
                                         "org.bluez.LEAdvertisingManager1")
        self.current_adv = None
        self.ad_idx = 0
        self.lock = threading.Lock()

    def start_ad(self, minor):
        """Create and register a new ad object with given minor."""
        with self.lock:
            self.ad_idx += 1
            try:
                adv = TwistAdvertisement(self.bus, self.ad_idx, minor)
            except TypeError:
                # some Advertisement constructors may differ; fallback:
                adv = TwistAdvertisement(self.bus, self.ad_idx, minor)
            self.current_adv = adv
            try:
                self.ad_manager.RegisterAdvertisement(adv.get_path(), {},
                                                      reply_handler=lambda: print(f"Advertisement idx {self.ad_idx} registered"),
                                                      error_handler=lambda e: print("Ad register error:", e))
            except Exception as e:
                print("RegisterAdvertisement exception:", e)

    def stop_ad(self):
        with self.lock:
            if self.current_adv:
                try:
                    self.ad_manager.UnregisterAdvertisement(self.current_adv.get_path())
                    print("Advertisement unregistered")
                except Exception as e:
                    print("UnregisterAdvertisement failed:", e)
                # Release object
                try:
                    # ensure DBus object is freed; some implementations require explicit Release call or rely on GC
                    if hasattr(self.current_adv, "Release"):
                        self.current_adv.Release()
                except Exception:
                    pass
                self.current_adv = None

# ------------------------
# Main TCU logic: state machine, sensor monitoring, beacon loop
# ------------------------
class TwistTCU:
    def __init__(self):
        global bus, app
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        self.bus = dbus.SystemBus()
        bus = self.bus
        # find adapter path that has LEAdvertisingManager1
        om = dbus.Interface(self.bus.get_object("org.bluez", "/"), "org.freedesktop.DBus.ObjectManager")
        objects = om.GetManagedObjects()
        adapter_path = None
        for path, props in objects.items():
            if "org.bluez.LEAdvertisingManager1" in props:
                adapter_path = path
                break
        if not adapter_path:
            raise RuntimeError("No BLE adapter with LEAdvertisingManager1 found")
        self.adapter_path = adapter_path
        self.beacon_ctrl = BeaconController(self.bus, self.adapter_path)

        # register a basic GATT Application if you wish (reuse existing Application)
        self.app = Application(self.bus)
        # register a service that will be used for owner connection, token, secure char, etc.
        # We reuse BluetoothService from earlier conversation if present (user can keep their GATT classes)
        # For demo, add minimal service registration using service.py
        svc = BluetoothService(self.bus, 0)
        self.app.add_service(svc)
        self.app.register()
        print("GATT application registered")

        # pairing agent
        try:
            agent = NoInputNoOutputAgent(self.bus)
            mgr = dbus.Interface(self.bus.get_object("org.bluez", "/org/bluez"), "org.bluez.AgentManager1")
            try:
                mgr.RegisterAgent("/test/agent", "NoInputNoOutput")
            except Exception:
                pass
            mgr.RequestDefaultAgent("/test/agent")
            print("Agent registered")
        except Exception as e:
            print("Agent registration failed:", e)

        # DBus PropertiesChanged to track device connect/disconnect
        self.bus.add_signal_receiver(self.properties_changed,
                                     dbus_interface="org.freedesktop.DBus.Properties",
                                     signal_name="PropertiesChanged",
                                     path="/org/bluez",
                                     arg0="org.bluez.Device1",
                                     sender_keyword="sender")

        # other state
        self.state = STATE_PAIRED_SAFE
        self.authorized_device_path = None
        self.sensor = None
        self.beacon_thread = threading.Thread(target=self.beacon_loop, daemon=True)
        self.sensor_thread = threading.Thread(target=self.sensor_loop, daemon=True)

    def properties_changed(self, interface, changed, invalidated, path, sender=None):
        """DBus PropertiesChanged callback - only interested in org.bluez.Device1/Connected property."""
        global owner_connected, last_owner_disconnect_time, authorized_device_path
        try:
            if interface != "org.bluez.Device1":
                return
            if "Connected" not in changed:
                return
            connected = bool(changed["Connected"])
            mac = path_to_mac(path)
            print(f"[DBUS] Device {mac} Connected={connected}")
            if connected:
                owner_connected = True
                last_owner_disconnect_time = None
                # Do not assume this is authorized; your GATT token characteristic handler should set authorized_device_path
                # Keep state in paired_safe while owner is connected
                with state_lock:
                    self.state = STATE_PAIRED_SAFE
                set_led(True)
            else:
                owner_connected = False
                last_owner_disconnect_time = time.time()
                set_led(False)
                # schedule arming after a delay
                def arm_delay_cb():
                    # only arm if still not connected
                    if not owner_connected:
                        with state_lock:
                            self.state = STATE_ARMED_MONITOR
                        print("[STATE] Transition -> ARMED_MONITOR")
                    return False
                GLib.timeout_add_seconds(int(ARM_DELAY_AFTER_OWNER_LEAVES), lambda: arm_delay_cb() or False)
        except Exception as e:
            print("properties_changed handler error:", e)

    def start(self):
        # init sensor
        try:
            self.sensor = MPU6050()
        except Exception as e:
            print("MPU6050 init failed:", e)
            self.sensor = None

        # start threads
        self.beacon_thread.start()
        self.sensor_thread.start()
        # mainloop keeps running via GLib (GATT app uses GLib.MainLoop elsewhere)
        print("TCU started")

    def stop(self):
        stop_event.set()
        self.beacon_ctrl.stop_ad()
        GPIO.cleanup()

    # sensor loop
    def sensor_loop(self):
        if not self.sensor:
            print("No sensor available, sensor loop will be idle")
            while not stop_event.is_set():
                time.sleep(1)
            return

        # simple threshold with debounce
        last_trigger_ts = 0
        while not stop_event.is_set():
            try:
                ax, ay, az = self.sensor.read_accel_g()
                g_norm = (ax * ax + ay * ay + az * az) ** 0.5
                # subtract 1g for gravity to approximate movement magnitude
                movement = abs(g_norm - 1.0)
                # print(f"ACC g_norm={g_norm:.3f} movement={movement:.3f}")
                if movement >= ACCEL_THRESHOLD:
                    now = int(time.time() * 1000)
                    if now - last_trigger_ts >= DEBOUNCE_MS:
                        last_trigger_ts = now
                        print("[SENSOR] Movement detected:", movement)
                        log_event({"event": "sensor_trigger", "movement": movement})
                        self.on_intrusion_detected()
                time.sleep(0.05)
            except Exception as e:
                print("Sensor read error:", e)
                time.sleep(0.5)

    def on_intrusion_detected(self):
        with state_lock:
            if self.state == STATE_DISTRESS:
                return
            print("[ALERT] Intrusion detected -> switching to DISTRESS")
            self.state = STATE_DISTRESS
        # start siren in background
        threading.Thread(target=sound_siren, args=(15,), daemon=True).start()
        log_event({"event": "intrusion", "state": "DISTRESS"})
        # optionally post to cloud (implement HTTP call here if required)

    # beacon loop - controls re-registration frequency depending on state
    def beacon_loop(self):
        global ad_index
        while not stop_event.is_set():
            with state_lock:
                cur_state = self.state
            if cur_state == STATE_PAIRED_SAFE:
                # don't advertise while owner connected
                self.beacon_ctrl.stop_ad()
                time.sleep(1)
                continue
            elif cur_state == STATE_ARMED_MONITOR:
                # low-frequency beacon with MINOR_ARMED
                try:
                    self.beacon_ctrl.start_ad(MINOR_ARMED)
                    time.sleep(0.5)  # give a small window to broadcast
                    self.beacon_ctrl.stop_ad()
                except Exception as e:
                    print("Beacon error (armed):", e)
                time.sleep(ARMED_BEACON_INTERVAL)
            elif cur_state == STATE_DISTRESS:
                # high-frequency distress beacon until reset
                try:
                    self.beacon_ctrl.start_ad(MINOR_DISTRESS)
                    time.sleep(0.25)
                    self.beacon_ctrl.stop_ad()
                except Exception as e:
                    print("Beacon error (distress):", e)
                time.sleep(DISTRESS_BEACON_INTERVAL)
            else:
                time.sleep(1)

# ------------------------
# Minimal BluetoothService / Characteristics
# ------------------------
# Reuse or copy your secure TokenCharacteristic and SecureCharacteristic classes here.
# This basic skeleton just exposes a minimal service so owner can connect and write the token.
class BluetoothService(Service):
    def __init__(self, bus, index):
        super().__init__(bus, index, "1234", True)
        # You should add TokenCharacteristic and SecureCharacteristic classes similar to earlier code
        # For this module we assume you have those classes in your repo and use them here.
        # Example:
        # self.add_characteristic(TokenCharacteristic(bus, 0, self))
        # self.add_characteristic(SecureCharacteristic(bus, 1, self))

# ------------------------
# Graceful shutdown
# ------------------------
def sigterm_handler(signum, frame):
    print("Signal received, shutting down")
    try:
        tcu.stop()
    except Exception:
        pass
    sys.exit(0)

signal.signal(signal.SIGINT, sigterm_handler)
signal.signal(signal.SIGTERM, sigterm_handler)

# ------------------------
# Main entry
# ------------------------
if __name__ == "__main__":
    try:
        gpio_setup()
        set_led(False)
        tcu = TwistTCU()
        tcu.start()
        # keep the GLib main loop running so DBus signals and GATT remain active
        mainloop = GLib.MainLoop()
        mainloop.run()
    except Exception as e:
        print("Fatal error:", e)
        traceback.print_exc()
        try:
            GPIO.cleanup()
        except Exception:
            pass
        sys.exit(1)
