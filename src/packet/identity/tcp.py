from .. import common

from . import core
from . import ip

from .core import uint16pack, uint16unpack


class TCP(core.CarrierProtocol):
    name = "tcp"

        __slots__ = {}

    def __init__(self, data, prev):
        super().__init__(data, prev)
        self._calculate_offsets()

    def _calculate_offsets(self):
        # Fixed offsets.
        pass


    def replace_hosts(self, hostmap):
        pass


    def get_attributes(self):
        """Retrieve a set of attributes describing fields in this protocol."""
        return {
        }

    def set_attributes(self, attrs):
        """Alter packet data to match a set of protocol attributes."""


    # <attr> = <key> "=" <value>
    # <attrstr> = <attr> | <attr> ";" <attrstr>
    #
    # Attributes are seperated by semicolons, which contain colon-seperated key-value pairs.
    # Valid keys are 
    @staticmethod
    def build_attributes(attrstr):
        """Creates a set of attributes from an attribute string."""
        attrdict = {}

        attrs = attrstr.split(";")
        for attr in attrs:
            try:
                # Split into kvp.
                k, v = attr.split("=")

            except ValueError:
                # Skip malformed attribute.
                pass

        return attrdict

    @staticmethod
    def interpret_packet(data, parent):
        """Interpret packet data for this protocol."""
        instance = TCP(data, parent)
        return instance

core.register_protocol(TCP)
ip.regsiter_ip_protocol(TCP.name, ip.PROTO_TCP)
