import sys
import struct

from . import core
from . import eth

identifier = "ip4"

def identify(packet, offset):
    attrs = {}
    packet.identity.append(core.ProtocolIdentity(identifier, attrs, offset))


def prototype(attrstr):
    pass


def modify(packet, ididx, prototype):
    pass


def register(ip4proto, module):
    registry[ip4proto] = module

registry = {}

eth.register(eth.ETHERTYPE_IP4, sys.modules[__name__])
