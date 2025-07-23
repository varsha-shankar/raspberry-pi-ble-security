import dbus
import dbus.service

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
            service_props = dbus.Dictionary({}, signature='sv')
            service_props[GATT_SERVICE_IFACE] = dbus.Dictionary({
                'UUID': dbus.String(service.uuid),
                'Primary': dbus.Boolean(service.primary),
                'Characteristics': dbus.Array(
                    service.get_characteristic_paths(),
                    signature='o'
                    )
        }, signature='sv')
        response[service.get_path()] = service_props

        for chrc in service.get_characteristics():
            chrc_props = dbus.Dictionary({}, signature='sv')
            chrc_props[GATT_CHRC_IFACE] = dbus.Dictionary({
                'Service': dbus.ObjectPath(service.get_path()),
                'UUID': dbus.String(chrc.uuid),
                'Flags': dbus.Array(chrc.flags, signature='s'),
                'Value': dbus.Array(chrc.value, signature='y')
            }, signature='sv')
            response[chrc.get_path()] = chrc_props
        return response  # ✅ move this outside the loop

    def register(self):
        bus = self.bus
        adapter = self.find_adapter()
        if not adapter:
            print("GattManager1 interface not found")
            return

        service_manager = dbus.Interface(
            bus.get_object(BLUEZ_SERVICE_NAME, adapter),
            GATT_MANAGER_IFACE)

        service_manager.RegisterApplication(self.get_path(), {},
            reply_handler=self.register_app_cb,
            error_handler=self.register_app_error_cb)

    def find_adapter(self):
        remote_om = dbus.Interface(
            self.bus.get_object(BLUEZ_SERVICE_NAME, '/'),
            DBUS_OM_IFACE)
        objects = remote_om.GetManagedObjects()

        for o, props in objects.items():
            if GATT_MANAGER_IFACE in props:
                return o
        return None

    def register_app_cb(self):
        print("GATT application registered")

    def register_app_error_cb(self, error):
        print("Failed to register application: " + str(error))

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
                'Primary': self.primary,
                'Characteristics': dbus.Array(
                    self.get_characteristic_paths(),
                    signature='o')
            }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_characteristic(self, characteristic):
        self.characteristics.append(characteristic)

    def get_characteristic_paths(self):
        result = []
        for chrc in self.characteristics:
            result.append(chrc.get_path())
        return result

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
                'Flags': self.flags,
                'Value': self.value
            }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method(DBUS_PROP_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != GATT_CHRC_IFACE:
            raise InvalidArgsException()
        return self.get_properties()[interface]

    @dbus.service.method(GATT_CHRC_IFACE,
                        in_signature='a{sv}',
                        out_signature='ay')
    def ReadValue(self, options):
        print('Default ReadValue called, returning error')
        raise NotSupportedException()

    @dbus.service.method(GATT_CHRC_IFACE, in_signature='aya{sv}')
    def WriteValue(self, value, options):
        print('Default WriteValue called, returning error')
        raise NotSupportedException()

    @dbus.service.method(GATT_CHRC_IFACE)
    def StartNotify(self):
        print('Default StartNotify called, returning error')
        raise NotSupportedException()

    @dbus.service.method(GATT_CHRC_IFACE)
    def StopNotify(self):
        print('Default StopNotify called, returning error')
        raise NotSupportedException()

    @dbus.service.signal(DBUS_PROP_IFACE, signature='sa{sv}as')
    def PropertiesChanged(self, interface, changed, invalidated):
        pass