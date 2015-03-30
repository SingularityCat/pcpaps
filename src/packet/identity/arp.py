import struct

from . import core
from . import eth


class ARP(core.Protocol):
    name = "arp"

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
        instance = ARP(packet, offset)

core.register_protocol(ARP)
eth.register_ethertype(ARP.name, eth.ETHERTYPE_ARP)
