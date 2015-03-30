import struct

from . import core
from . import eth

# RFC 826:
#
#    ARP Ethernet packet data:
#        16.bit: (ar$hrd) Hardware address space (e.g., Ethernet,
#                         Packet Radio Net.)
#        16.bit: (ar$pro) Protocol address space.  For Ethernet
#                         hardware, this is from the set of type
#                         fields ether_typ$<protocol>.
#         8.bit: (ar$hln) byte length of each hardware address
#         8.bit: (ar$pln) byte length of each protocol address
#        16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
#        nbytes: (ar$sha) Hardware address of sender of this
#                         packet, n from the ar$hln field.
#        mbytes: (ar$spa) Protocol address of sender of this
#                         packet, m from the ar$pln field.
#        nbytes: (ar$tha) Hardware address of target of this
#                         packet (if known).
#        mbytes: (ar$tpa) Protocol address of target.


ARP_HARDWARE_ETHERNET = 1

# These match ethertypes.
ARP_PROTOCOL_IPV4 = 0x0800

ARP_OPCODE_REQUEST = 1
ARP_OPCODE_REPLY = 2

class ARP(core.Protocol):
    name = "arp"

    __slots__ = {"_htype", "_ptype", "_hlen", "_plen", "_opcode",
        "_sha", "_spa", "_tha", "_tpa"}

    def __init__(self, packet, offset):
        super().__init__(packet, offset)
        _calculate_offsets()

    def _calculate_offsets(self):
        # Fixed offsets.
        self._htype = slice(self.offset+0, self.offset+2)
        self._ptype = slice(self.offset+2, self.offset+4)
        self._hlen = self.offset+4
        self._plen = self.offset+5
        self._opcode = slice(self.offset+6, self.offset+8)

        # Variable offsets.
        hlen = self.packet.data[self._hlen]
        plen = self.packet.data[self._plen]

        varoff = self.offset+8

        _sha = slice(varoff, varoff+hlen)
        _spa = slice(varoff+hlen, varoff+hlen+plen)
        _tpa = slice(varoff+hlen+plen, varoff+2*hlen+plen)
        _tha = slice(varoff+2*hlen+plen, varoff+2*hlen+2*plen)

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
