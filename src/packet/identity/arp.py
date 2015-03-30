from .. import common

from . import core
from . import eth

from .core import uint16pack, uint16unpack

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


# ARP hardware address types.
ARP_HARDWARE_ETHERNET = 1

# ARP protocol address types. (these match ethertypes)
ARP_PROTOCOL_IPV4 = 0x0800

# ARP Opcodes.
ARP_OPCODE_REQUEST = 1
ARP_OPCODE_REPLY = 2


class ARP(core.Protocol):
    name = "arp"

    __slots__ = {"_htype", "_ptype", "_hlen", "_plen", "_opcode",
        "_sha", "_spa", "_tha", "_tpa"}

    def __init__(self, packet, offset):
        super().__init__(packet, offset)
        self._calculate_offsets()

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

        self._sha = slice(varoff, varoff+hlen)
        self._spa = slice(varoff+hlen, varoff+hlen+plen)
        self._tpa = slice(varoff+hlen+plen, varoff+2*hlen+plen)
        self._tha = slice(varoff+2*hlen+plen, varoff+2*hlen+2*plen)

    def get_attributes(self):
        """Retrieve a set of attributes describing fields in this protocol."""
        return {
            "htype": uint16unpack(self.packet.data[self._htype]),
            "ptype": uint16unpack(self.packet.data[self._ptype]),
            "hlen": self.packet.data[self._hlen],
            "plen": self.packet.data[self._plen],
            "opcode": uint16unpack(self.packet.data[self._opcode]),
            "sha": self.packet.data[self._sha],
            "spa": self.packet.data[self._spa],
            "tha": self.packet.data[self._tha],
            "tpa": self.packet.data[self._tpa]
        }

    def set_attributes(self, attrs):
        """Alter packet data to match a set of protocol attributes."""
        pass

    # ARP prototype attribute string format:
    # <attr> = <key> "=" <value>
    # <attrstr> = <attr> | <attr> ";" <attrstr>
    #
    # Attributes are seperated by semicolons, which contain colon-seperated key-value pairs.
    # Valid keys are "sha", "spa", "tha", "tpa" or "opcode"
    @staticmethod
    def build_attributes(attrstr):
        """Creates a set of ARP attributes from an attribute string."""
        attrdict = {}

        attrs = attrstr.split(";")
        for attr in attrs:
            try:
                # Split into kvp.
                k, v = attr.split("=")

                # Interpret integer fields. 
                if k == "htype" or k == "ptype" or k == "opcode":
                    i = common.parse_int(v)
                    # Check if integer is valid.
                    if i is not None:
                        attrdict[k] = i

                # Interpret (possible) MAC address fields.
                elif k == "sha" or k == "tha":
                    # First, try interpreting as a MAC address.
                    ha = common.mac_str2bin(v)
                    # Check if it's valid, if not, interpret as written hex encoded bytes.
                    if ha is None:
                        ha = common.parse_hexbytes(v)

                    if ha is not None:
                        attrdict[k] = ha

                # Interpret (possible) IPv4 address fields.
                elif k == "spa" or k == "tpa":
                    # First, try interpreting as an IPv4 address.
                    pa = common.ip4_str2bin(v)
                    # Check if it's valid, if not, interpret as written hex encoded bytes.
                    if pa is None:
                        pa = common.parse_hexbytes(v)

                    if pa is not None:
                        attrdict[k] = pa

            except ValueError:
                # Skip malformed attribute.
                pass

        return attrdict

    @staticmethod
    def interpret_packet(packet, offset):
        """Interpret packet data for this protocol."""
        instance = ARP(packet, offset)

core.register_protocol(ARP)
eth.register_ethertype(ARP.name, eth.ETHERTYPE_ARP)
