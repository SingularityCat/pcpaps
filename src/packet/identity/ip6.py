import struct

from . import core
from . import eth


class IPv6(core.Protocol):
    name = "ip6"

    def __init__(self, data, prev):
        super().__init__(data, prev)

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
    def interpret_packet(data, parent):
        """Interpret packet data for this protocol."""
        instance = IPv6(data, parent)
        return instance

core.register_protocol(IPv6)
eth.register_ethertype(IPv6.name, eth.ETHERTYPE_IP6)
