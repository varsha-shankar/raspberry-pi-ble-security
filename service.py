import dbus
import dbus.service
from enum import Enum, IntFlag

# DBus Interfaces
BLUEZ_SERVICE_NAME = 'org.bluez'
GATT_MANAGER_IFACE = 'org.bluez.GattManager1'
GATT_SERVICE_IFACE = 'org.bluez.GattService1'
GATT_CHRC_IFACE = 'org.bluez.GattCharacteristic1'
DBUS_OM_IFACE = 'org.freedesktop.DBus.ObjectManager'
DBUS_PROP_IFACE = 'org.freedesktop.DBus.Properties'

class InvalidArgsException(dbus.exceptions.DBusException):
    _dbus_error_name = 'org.freedesktop.DBus.Error.InvalidArgs'

class NotSupportedException(dbus.exceptions.DBusException):
    _dbus_error_name = 'org.bluez.Error.NotSupported'

# --------------------------------------------------------
# Two-wheeler simulator characteristic definitions
# --------------------------------------------------------
class TwoWheelerCharID(Enum):
    IGNITION_STATE   = 0
    BATTERY_VOLTAGE  = 1
    ODOMETER_VALUE   = 2
    ENGINE_TEMP      = 3
    FUEL_LEVEL       = 4
    SPEED            = 5

class CharProperty(IntFlag):
    NONE      = 0x00
    READ      = 0x01
    WRITE     = 0x02
    NOTIFY    = 0x04
    READWRITE = READ | WRITE

CHAR_UUIDS = {
    TwoWheelerCharID.IGNITION_STATE:  "12345678-1234-5678-1234-56789abcde01",
    TwoWheelerCharID.BATTERY_VOLTAGE: "12345678-1234-5678-1234-56789abcde02",
    TwoWheelerCharID.ODOMETER_VALUE:  "12345678-1234-5678-1234-56789abcde03",
    TwoWheelerCharID.ENGINE_TEMP:     "12345678-1234-5678-1234-56789abcde04",
    TwoWheelerCharID.FUEL_LEVEL:      "12345678-1234-5678-1234-56789abcde05",
    TwoWheelerCharID.SPEED:           "12345678-1234-5678-1234-56789abcde06",
}

CHAR_PROPERTIES = {
    TwoWheelerCharID.IGNITION_STATE:  CharProperty.READWRITE | CharProperty.NOTIFY,
    TwoWheelerCharID.BATTERY_VOLTAGE: CharProperty.READWRITE,
    TwoWheelerCharID.ODOMETER_VALUE:  CharProperty.READWRITE,
    TwoWheelerCharID.ENGINE_TEMP:     CharProperty.READWRITE,
    TwoWheelerCharID.FUEL_LEVEL:      CharProperty.READWRITE,
    TwoWheelerCharID.SPEED:           CharProperty.READWRITE,
}

char_values = {
    TwoWheelerCharID.IGNITION_STATE:  False,
    TwoWheelerCharID.BATTERY_VOLTAGE: 15,
    TwoWheelerCharID.ODOMETER_VALUE:  12345,
    TwoWheelerCharID.ENGINE_TEMP:     75.0,
    TwoWheelerCharID.FUEL_LEVEL:      55,
    TwoWheelerCharID.SPEED:           0,
}

# --------------------------------------------------------
# Framework
# --------------------------------------------------------
class Application(dbus.service.Object):
    def __init__(self, bus):
        self.bus = bus
        self.path = '/'
        self.services = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_service(self, service):
        self.services.append(service)

    @dbus.service.method(DBUS_OM_IFACE, out_signature='a{oa{sa{sv}}}')
    def GetManagedObjects(self):
        response = dbus.Dictionary({}, signature='oa{sa{sv}}')
        for service in self.services:
            response[service.get_path()] = dbus.Dictionary(
                service.get_properties(), signature='sa{sv}'
            )
            for chrc in service.get_characteristics():
                response[chrc.get_path()] = dbus.Dictionary(
                    chrc.get_properties(), signature='sa{sv}'
                )
                if hasattr(chrc, "descriptors"):
                    for d in chrc.descriptors:
                        response[d.get_path()] = dbus.Dictionary(
                            d.get_properties(), signature='sa{sv}'
                        )
        return response

class Service(dbus.service.Object):
    def __init__(self, bus, index, uuid, primary):
        self.path = '/org/bluez/example/service' + str(index)
        self.bus = bus
        self.uuid = uuid
        self.primary = primary
        self.characteristics = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        return {
            GATT_SERVICE_IFACE: {
                'UUID': self.uuid,
                'Primary': dbus.Boolean(self.primary),
                'Includes': dbus.Array([], signature='o'),
            }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_characteristic(self, characteristic):
        self.characteristics.append(characteristic)

    def get_characteristic_paths(self):
        return [c.get_path() for c in self.characteristics]

    def get_characteristics(self):
        return self.characteristics

    @dbus.service.method(DBUS_PROP_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != GATT_SERVICE_IFACE:
            raise InvalidArgsException()
        return self.get_properties()[interface]

class Characteristic(dbus.service.Object):
    def __init__(self, bus, index, uuid, flags, service):
        self.path = service.path + '/char' + str(index)
        self.bus = bus
        self.uuid = uuid
        self.service = service
        self.flags = flags
        self.value = []
        dbus.service.Object.__init__(self, bus, self.path)
        
    def get_properties(self):
        return {
            GATT_CHRC_IFACE: {
                'Service': self.service.get_path(),
                'UUID': self.uuid,
                'Flags': dbus.Array(self.flags, signature='s'),
                'Value': dbus.Array(self.value, signature='y'),
            }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method(DBUS_PROP_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != GATT_CHRC_IFACE:
            raise InvalidArgsException()
        return self.get_properties()[interface]

    @dbus.service.method(GATT_CHRC_IFACE, in_signature='a{sv}', out_signature='ay')
    def ReadValue(self, options):
        raise NotSupportedException()

    @dbus.service.method(GATT_CHRC_IFACE, in_signature='aya{sv}')
    def WriteValue(self, value, options):
        raise NotSupportedException()

    @dbus.service.method(GATT_CHRC_IFACE)
    def StartNotify(self):
        raise NotSupportedException()

    @dbus.service.method(GATT_CHRC_IFACE)
    def StopNotify(self):
        raise NotSupportedException()

    @dbus.service.signal(DBUS_PROP_IFACE, signature='sa{sv}as')
    def PropertiesChanged(self, interface, changed, invalidated):
        pass

# --------------------------------------------------------
# Custom characteristic & service for 2-wheeler simulator
# --------------------------------------------------------
class TwoWheelerCharacteristic(Characteristic):
    # v-- MODIFIED TO ACCEPT LED DEVICE --v
    def __init__(self, bus, index, char_id, service, led_device=None):
        self.char_id = char_id
        uuid = CHAR_UUIDS[char_id]
        flags = []
        if CHAR_PROPERTIES[char_id] & CharProperty.READ:
            flags.append("read")
        if CHAR_PROPERTIES[char_id] & CharProperty.WRITE:
            flags.append("write")
        if CHAR_PROPERTIES[char_id] & CharProperty.NOTIFY:
            flags.append("notify")
        
        super().__init__(bus, index, uuid, flags, service)
        self.notifying = False
        self.led = led_device # Store the LED object
    # ^-- END MODIFICATION --^

    def update_and_notify_state(self, new_state):
        if char_values[self.char_id] == new_state:
            return

        char_values[self.char_id] = new_state
        if new_state:
            print("IGNITION STATE CHANGED TO: ON")
            # v-- ADDED LED CONTROL --v
            if self.led: self.led.on()
            # ^-- END ADDED CODE --^
        else:
            print("IGNITION STATE CHANGED TO: OFF")
            # v-- ADDED LED CONTROL --v
            if self.led: self.led.off()
            # ^-- END ADDED CODE --^
        
        if self.notifying:
            print("Notifying mobile app of ignition state change...")
            new_value_dbus = [dbus.Byte(1 if new_state else 0)]
            self.PropertiesChanged(GATT_CHRC_IFACE, {'Value': new_value_dbus}, [])

    @dbus.service.method(GATT_CHRC_IFACE)
    def StartNotify(self):
        if self.notifying: return
        self.notifying = True
        print(f"Notifications enabled for {self.char_id.name}")

    @dbus.service.method(GATT_CHRC_IFACE)
    def StopNotify(self):
        if not self.notifying: return
        self.notifying = False
        print(f"Notifications disabled for {self.char_id.name}")

    @dbus.service.method(GATT_CHRC_IFACE, in_signature='a{sv}', out_signature='ay')
    def ReadValue(self, options):
        value = char_values[self.char_id]
        if isinstance(value, bool):
            if value: print("App read request: Ignition is ON")
            else: print("App read request: Ignition is OFF")     
            return [dbus.Byte(1 if value else 0)]
        elif isinstance(value, int):
            return [dbus.Byte((value >> (8 * i)) & 0xFF) for i in range(4)]
        elif isinstance(value, float):
            mv = int(value * 100)
            return [dbus.Byte((mv >> (8 * i)) & 0xFF) for i in range(2)]
        return []

    @dbus.service.method(GATT_CHRC_IFACE, in_signature='aya{sv}')
    def WriteValue(self, value, options):
        if not (CHAR_PROPERTIES[self.char_id] & CharProperty.WRITE):
            raise NotSupportedException()
        
        if self.char_id == TwoWheelerCharID.IGNITION_STATE:
            self.update_and_notify_state(bool(value[0]))
        elif self.char_id == (TwoWheelerCharID.ODOMETER_VALUE):
            new_val = int.from_bytes(value, byteorder="little")
            print("Odometer value (Km) : "+bytes(value).decode('utf-8'))
            char_values[self.char_id] = new_val
        # ... (rest of the method is unchanged)

class TwoWheelerService(Service):
    # v-- MODIFIED TO ACCEPT LED DEVICE --v
    def __init__(self, bus, index, ignition_led=None):
        super().__init__(bus, index,
            "12345678-1234-5678-1234-56789abcde00", True)
        self.ignition_led = ignition_led # Store the object
        self.add_characteristics(bus)
    # ^-- END MODIFICATION --^

    # v-- MODIFIED TO PASS LED DEVICE TO CHARACTERISTIC --v
    def add_characteristics(self, bus):
        idx = 0
        for cid in TwoWheelerCharID:
            # Pass the LED object only to the ignition characteristic
            led_device = self.ignition_led if cid == TwoWheelerCharID.IGNITION_STATE else None
            self.add_characteristic(TwoWheelerCharacteristic(bus, idx, cid, self, led_device=led_device))
            idx += 1
    # ^-- END MODIFICATION --^