import struct

from . import core
from . import eth


# RFC 791
#
# Internet Header Format
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|  IHL  |Type of Service|          Total Length         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Identification        |Flags|      Fragment Offset    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Time to Live |    Protocol   |         Header Checksum       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Source Address                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Destination Address                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Options                    |    Padding    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# The checksum algorithm is:
#      The checksum field is the 16 bit one's complement of the one's
#      complement sum of all 16 bit words in the header.  For purposes of
#      computing the checksum, the value of the checksum field is zero.

def ip4_checksum(hdr):
    n32words, rem = divmod(len(hdr), 4)

    # header must be a multiple of 4 bytes large,
    # and must contain at least 5 of these.
    if rem != 0 or nwords > 5:
        # !!?
        return None

    n16words = n32words * 2

    # generate list of 16-bit words.
    words = [word for word in struct.Struct("!"+"H"*n16words).unpack(hdr)]
    words[5] = 0 # Checksum word is 0 for checksum validation.

    ocsum = 0

    for word in words:
        acc = ocsum + word
        carry = acc & ~0xFFFF) >> 16
        ocsum = acc + carry

    return bytes(divmod(ocsum, 256))


class IPv4(core.CarrierProtocol):
    name = "ip4"

    __slots__ = {"_ver_ihl", "_tos", "_len",
                 "_id", "_flags_fragoff",
                 "_ttl", "_proto", "_chksum",
                 "_saddr",
                 "_daddr"}


    def __init__(self, packet, offset):
        """"""
        super().__init__(packet, offset)
        self._calculate_offsets()


    def _calculate_offsets(self):
        self._ver_ihl = offset+0
        self._tos = offset+1
        self._len = slice(offset+2, offset+4)
        self._id = slice(offset+4, offset+6)
        self._flags_fragoff = slice(offset+6, offset+8)
        self._ttl = offset+8
        self._proto = offset+9
        self._chksum = slice(offset+10, offset+12)
        self._saddr = slice(offset+12, offset+16)
        self._daddr = slice(offset+16, offset+20)

        # Get header length.
        ihl = self.packet.data[self._ver_ihl] & 0x0F

        self.payload_offset = offset+ihl


    def get_route(self):
        """Returns the route defined by this IP header."""
        return bytes()


    def get_route_reciprocal(self):
        """Returns the reciprocal route of this IP header."""
        return bytes()


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


def register_ip_protocol(protocol, protonum):
    """Associate a protocl name with a IP protocol number."""
    registry[protonum] = protocol

registry = {}

# Register protocol, and as an ethertype handler.
core.register_protocol(IPv4)
eth.register_ethertype(IPv4.name, eth.ETHERTYPE_IP4)
