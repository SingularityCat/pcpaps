"""
ip: 
Internet Protocol Number registry.
"""

from . import core


def register_ip_protocol(protoname, protonum):
    """Add a protocol number <-> name mapping."""
    ip_protocol_registry[protonum] = protoname


def lookup_ip_protocol(protonum):
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
