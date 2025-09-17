#!/usr/bin/env python3
# Minimal BLE test server for Raspberry Pi
# Advertises a connectable service with one read/write characteristic.
# Use nRF Connect or any BLE app to test connection.

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
import subprocess
import sys

from advertisement import Advertisement
from service import Application, Service, Characteristic
from agent import NoInputNoOutputAgent

# -----------------------------
# Config
# -----------------------------
LOCAL_NAME = "BLETestPi"
SERVICE_UUID = "00001234-0000-1000-8000-00805f9b34fb"
CHAR_UUID = "00005678-0000-1000-8000-00805f9b34fb"

# -----------------------------
# Advertisement
# -----------------------------
class GattAdvertisement(Advertisement):
    def __init__(self, bus, index):
        super().__init__(bus, index, "peripheral")
        self.add_service_uuid("1234")
        self.add_local_name(LOCAL_NAME)
        self.include_tx_power = True

# -----------------------------
# Simple GATT Service/Characteristic
# -----------------------------
class TestCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        super().__init__(bus, index, CHAR_UUID,
                         ["read", "write"], service)
        self.value = dbus.Array([], signature='y')

    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        print("📖 Read request:", list(self.value))
        return self.value

    @dbus.service.method("org.bluez.GattCharacteristic1",
                         in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        self.value = value
        print("✍️ Write request:", list(value))

class TestService(Service):
    def __init__(self, bus, index):
        super().__init__(bus, index, SERVICE_UUID, True)
        self.add_characteristic(TestCharacteristic(bus, 0, self))

# -----------------------------
# Bluetooth App
# -----------------------------
class BluetoothApplication:
    def __init__(self):
        self.bus = dbus.SystemBus()
        self.app = Application(self.bus)

        self.adapter_path = self._find_adapter()
        if not self.adapter_path:
            raise RuntimeError("BLE adapter not found")

        self.ad_manager = dbus.Interface(
            self.bus.get_object("org.bluez", self.adapter_path),
            "org.bluez.LEAdvertisingManager1")
        self.service_manager = dbus.Interface(
            self.bus.get_object("org.bluez", self.adapter_path),
            "org.bluez.GattManager1")

    def _find_adapter(self):
        om = dbus.Interface(self.bus.get_object("org.bluez", "/"),
                            "org.freedesktop.DBus.ObjectManager")
        objects = om.GetManagedObjects()
        for path, props in objects.items():
            if "org.bluez.LEAdvertisingManager1" in props:
                return path
        return None

    def run(self):
        service = TestService(self.bus, 0)
        self.app.add_service(service)

        adv = GattAdvertisement(self.bus, 0)

        def _app_registered():
            print("✅ GATT app registered")
            self.ad_manager.RegisterAdvertisement(
                adv.get_path(), {},
                reply_handler=lambda: print("✅ Advertisement registered"),
                error_handler=lambda e: print(f"❌ Ad register error: {e}")
            )

        def _app_error(e):
            print(f"❌ Failed to register GATT app: {e}")
            sys.exit(1)

        self.service_manager.RegisterApplication(
            self.app.get_path(), {},
            reply_handler=_app_registered,
            error_handler=_app_error)

        GLib.MainLoop().run()

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    # Register no-input agent for Just Works pairing
    agent = NoInputNoOutputAgent(bus)
    mgr = dbus.Interface(bus.get_object("org.bluez", "/org/bluez"),
                         "org.bluez.AgentManager1")
    try:
        mgr.RegisterAgent("/test/agent", "NoInputNoOutput")
    except dbus.exceptions.DBusException as e:
        if "AlreadyExists" not in str(e):
            raise
    mgr.RequestDefaultAgent("/test/agent")
    print("🔑 Agent registered")

    # Ensure adapter is discoverable and pairable
    subprocess.run(["bluetoothctl", "discoverable", "on"], check=False)
    subprocess.run(["bluetoothctl", "pairable", "on"], check=False)

    app = BluetoothApplication()
    try:
        app.run()
    except KeyboardInterrupt:
        sys.exit(0)
