import struct

from .. import common

from . import core
from . import eth
from .core import uint16pack, uint16unpack

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

# Register protocol, as a ethertype handler and as a linktype handler.
core.register_protocol(IPv6)
core.register_linktype(IPv6.name, common.LinkType.IPV6.value)
eth.register_ethertype(IPv6.name, eth.ETHERTYPE_IP6)
