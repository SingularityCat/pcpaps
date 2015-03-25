import sys
import struct

from . import core
from . import ethernet

identifier = "ip4"

def identify(packet, offset):
    attrs = {}
    packet.identity.append(core.ProtocolIdentity(identifier, attrs, offset))


def prototype(attrstr):
    pass


def modify(packet, prototype):
    pass


def register(ip4proto, module):
    registry[ip4proto] = module

registry = {}

ethernet.register(ethernet.ETHERTYPE_IP4, sys.modules[__name__])
