"""
ip: 
Internet Protocol Number registry.
"""

from . import core


def register_ip_protocol(protonum, protoname):
    """Add a protocol number <-> name mapping."""
    ip_protocol_registry[protonum] = protoname


def lookup_ip_protocol(protonum):
    if protonum in ip_protocol_registry:
        protoname = ip_protocol_registry[protonum]
        return core.lookup_protocol(protoname)
    return None

ip_protocol_registry = {}
