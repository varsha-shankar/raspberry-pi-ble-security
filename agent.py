import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib

AGENT_INTERFACE = "org.bluez.Agent1"
AGENT_PATH = "/test/agent"

class NoInputNoOutputAgent(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, AGENT_PATH)

    @dbus.service.method(AGENT_INTERFACE, in_signature="", out_signature="")
    def Release(self):
        print("Agent released")

    @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="")
    def RequestAuthorization(self, device):
        print(f"Authorization requested for {device}")
        return

    @dbus.service.method(AGENT_INTERFACE, in_signature="os", out_signature="")
    def AuthorizeService(self, device, uuid):
        print(f"Service authorized: {uuid} for device {device}")
        return

    @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="s")
    def RequestPinCode(self, device):
        print(f"RequestPinCode for {device}")
        return "0000"

    @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="u")
    def RequestPasskey(self, device):
        print(f"RequestPasskey for {device}")
        return dbus.UInt32(123456)

    @dbus.service.method(AGENT_INTERFACE, in_signature="ou", out_signature="")
    def DisplayPasskey(self, device, passkey):
        print(f"DisplayPasskey: {passkey} for {device}")

    @dbus.service.method(AGENT_INTERFACE, in_signature="ou", out_signature="")
    def RequestConfirmation(self, device, passkey):
        print(f"Confirm passkey {passkey} for {device}")
        return  # auto-confirm

    @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="")
    def RequestPairingConsent(self, device):
        print(f"Pairing consent requested for {device}")
        return

    @dbus.service.method(AGENT_INTERFACE, in_signature="", out_signature="")
    def Cancel(self):
        print("Agent request cancelled")