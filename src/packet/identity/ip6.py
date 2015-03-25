import sys
import struct

from . import core
from . import ethernet

identifier = "ip6"


def identify(packet, offset):
    attrs = {}
    packet.identity.append(core.ProtocolIdentity(identifier, attrs, offset))


def prototype(attrstr):
    pass


def modify(packet, ididx, prototype):
    pass


def register(ip6proto, offset, module):
    registry[ip6proto] = module


registry = {}

ethernet.register(ethernet.ETHERTYPE_IP6, sys.modules[__name__])
