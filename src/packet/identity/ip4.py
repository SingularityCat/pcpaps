import struct

from . import core
from . import eth


class IPv4(core.Protocol):
    name = "ip4"

    def __init__(self, packet, offset):
        super().__init__(packet, offset)

    def get_attributes(self):
        """Retrieve a set of attributes describing fields in this protocol."""
        return {}

    def set_attributes(self, attrs):
        """Alter packet data to match a set of protocol attributes."""
        pass

    @staticmethod
    def build_attributes(attrstr):
        """Build attribute dict from string."""
        attrs = {}
        return attrs

    @staticmethod
    def interpret_packet(packet, offset):
        """Interpret packet data for this protocol."""
        instance = IPv4(packet, offset)

core.register_protocol(IPv4)
eth.register_ethertype(IPv4.name, eth.ETHERTYPE_IP4)
