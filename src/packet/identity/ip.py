"""
ip: 
Internet Protocol Number registry and checksum algorithm.
"""
import struct

from . import core


# The checksum algorithm is:
#      The checksum field is the 16 bit one's complement of the one's
#      complement sum of all 16 bit words in the header.  For purposes of
#      computing the checksum, the value of the checksum field is zero.

def checksum(data):
    """General implementation of the IP checksum algorithm."""
    n16words, rem = divmod(len(data), 2)

    if rem != 0:
        # Argument is not in terms of 16-bit words.
        return None

    # generate list of 16-bit words.
    words = [word for word in struct.Struct("!"+"H"*n16words).unpack(data)]

    ocsum = 0
    for word in words:
        # One's complement addition of 16-bit words.
        acc = ocsum + word
        carry = acc >> 16
        ocsum = (acc + carry) & 0xFFFF

    b1, b2 = divmod(ocsum, 256)
    return bytes((~b1 & 0xFF, ~b2 & 0xFF))


def register_ip_protocol(protoname, protonum):
    """Add a protocol number <-> name mapping."""
    ip_protocol_registry[protonum] = protoname


def lookup_ip_protocol(protonum):
    """Looks up a protocol name from number."""
    if protonum in ip_protocol_registry:
        protoname = ip_protocol_registry[protonum]
        return core.lookup_protocol(protoname)
    return None


ip_protocol_registry = {}

# IANA: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
PROTO_ICMP = 1
PROTO_IPV4 = 4
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_IPV6 = 41
PROTO_IPV6_ICMP = 58
PROTO_ETHERIP = 97
