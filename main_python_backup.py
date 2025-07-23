import dbus
import dbus.exceptions
import dbus.mainloop.glib
import dbus.service
import signal
import sys
import RPi.GPIO as GPIO

from gi.repository import GLib

from advertisement import Advertisement
from service import Application, Service, Characteristic
from agent import NoInputNoOutputAgent

# Setup buzzer pin
BUZZER_PIN = 18
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
GPIO.setup(BUZZER_PIN, GPIO.OUT)

# DBus Interfaces
BLUEZ_SERVICE_NAME = 'org.bluez'
LE_ADVERTISING_MANAGER_IFACE = 'org.bluez.LEAdvertisingManager1'
DBUS_OM_IFACE = 'org.freedesktop.DBus.ObjectManager'
DBUS_PROP_IFACE = 'org.freedesktop.DBus.Properties'
app = None
        
class BluetoothAdvertisement(Advertisement):
    def __init__(self, bus, index):
        Advertisement.__init__(self, bus, index, 'peripheral')
        self.add_service_uuid('1234')
        self.add_local_name('rpi')
        self.include_tx_power = True

class BluetoothApplication:
    def __init__(self):
        self.bus = dbus.SystemBus()
        self.adapter = self.find_adapter()
        if not self.adapter:
            print("LEAdvertisingManager1 interface not found")
            print(f"using adapter: {self.adapter}")
            return

        self.ad_manager = dbus.Interface(
            self.bus.get_object(BLUEZ_SERVICE_NAME, self.adapter),
            LE_ADVERTISING_MANAGER_IFACE)

        self.app = Application(self.bus)
        self.adv = BluetoothAdvertisement(self.bus, 0)

    def find_adapter(self):
        object_manager = dbus.Interface(
            self.bus.get_object(BLUEZ_SERVICE_NAME, '/'),
            DBUS_OM_IFACE)
        
        objects = object_manager.GetManagedObjects()
        for obj, props in objects.items():
            if LE_ADVERTISING_MANAGER_IFACE in props:
                return obj
        
        return self.app.find_adapter()

    def start_advertising(self):
        print("Starting advertising")
        self.ad_manager.RegisterAdvertisement(
            self.adv.get_path(),
            {},
            reply_handler=self.register_ad_cb,
            error_handler=self.register_ad_error_cb)

    def register_ad_cb(self):
        print("Advertisement registered successfully")

    def register_ad_error_cb(self, error):
        print(f"Failed to register advertisement: {error}")

    def run(self):
        try:
            # Initialize service first
            service = BluetoothService(self.bus, 0)
            print(f"Registering service with UUID: {service.uuid}")
            self.app.add_service(service)
            # Then register application
            self.app.register()
            # Finally start advertising
            self.start_advertising()
            GLib.MainLoop().run()
        except Exception as e:
            print(f"Error: {e}")
            self.cleanup()
        
    def cleanup(self):
        try:
            print("🧹 Cleaning up BLE resources")
            if hasattr(self, 'adv'):
                self.adv.Release()

            if hasattr(self, 'app'):
                adapter = self.find_adapter()
                if adapter:
                    service_manager = dbus.Interface(
                        self.bus.get_object(BLUEZ_SERVICE_NAME, adapter),
                        'org.bluez.GattManager1')
                    service_manager.UnregisterApplication(self.app.get_path())
                    print("Unregistered GATT app")
        except Exception as e:
            print(f"Cleanup error: {e}")

class BluetoothService(Service):
    def __init__(self, bus, index):
        Service.__init__(self, bus, index, '1234', True)
        self.add_characteristic(BluetoothCharacteristic(bus, 0, self))

class BluetoothCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        Characteristic.__init__(
            self, bus, index,
            '5678',
            ['read', 'write', 'write-without-response', 'notify'],
            service)
       # self.timeout_id = GLib.timeout_add_seconds(5,self._on_timeout)
        self.value = []
        print(f"Initialized characteristic {self.uuid} with flags {self.flags}")

    def ReadValue(self, options):
        print(f"Read request: {self.value}")
        return self.value
     
    @dbus.service.method('org.bluez.GattCharacteristic1',
                         in_signature='aya{sv}', out_signature='')
    def WriteValue(self, value, options):
        print(f"Write request: {value}")
        print("✅ WriteValue triggered!")
        print(f"Raw DBus value: {value}")
        try:
             print(f"Converted: {list(value)}")
        except:
            pass
        self.value = value
        self.PropertiesChanged(
            'org.bluez.GattCharacteristic1',
            {'Value': self.value}, [])
    
    def _on_timeout(self):
        print("Error: Device idin't respond in 5 seconds")
        self.timeout_id = None

def signal_handler(sig, frame):
    print("🛑 Caught exit signal, cleaning up...")
    GPIO.output(BUZZER_PIN, GPIO.LOW)
    GPIO.cleanup()
    if app:
        app.cleanup()
    sys.exit(0)
    
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def interfaces_added_handler(object_path, interfaces_and_properties):
    if isinstance(interfaces_and_properties, dict) and 'org.bluez.Device1' in interfaces_and_properties:
        print(f"🔗 Device connected: {object_path}")

def interfaces_removed_handler(object_path, interfaces):
    if isinstance(interfaces, list) and 'org.bluez.Device1' in interfaces:
        print(f"🔌 Device disconnected: {object_path}")
        trigger_alarm()
        
def trigger_alarm():
    print(" Anti-theft alarm triggered! Phone disconnected.")
    GPIO.output(BUZZER_PIN, GPIO.HIGH)
    GLib.timeout_add_seconds(3, stop_alarm)  # Turn off after 3 seconds

def stop_alarm():
    GPIO.output(BUZZER_PIN, GPIO.LOW)
    return False  # Ensures this GLib timeout only runs once

if __name__ == "__main__":
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    
    # Register Agent
    agent = NoInputNoOutputAgent(bus)
    manager = dbus.Interface(bus.get_object("org.bluez", "/org/bluez"), "org.bluez.AgentManager1")
    manager.RegisterAgent("/test/agent", "NoInputNoOutput")
    print("Agent registered")
    manager.RequestDefaultAgent("/test/agent")
    print("Default agent set")
    
    bus.add_signal_receiver(
    interfaces_added_handler,
    dbus_interface="org.freedesktop.DBus.ObjectManager",
    signal_name="InterfacesAdded"
    )

    bus.add_signal_receiver(
    interfaces_removed_handler,
    dbus_interface="org.freedesktop.DBus.ObjectManager",
    signal_name="InterfacesRemoved"
    )
    # Run Bluetooth app
    app = BluetoothApplication()
    app.run()