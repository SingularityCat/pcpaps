import sys
import struct

from . import core
from . import eth

identifier = "arp"


def identify(packet, offset):
    attrs = {}
    packet.identity.append(core.ProtocolIdentity(identity, attrs, offset))


def prototype(attrstr):
    pass


def modify(packet, ididx, prototype):
    pass


identity = "ip4"
eth.register(eth.ETHERTYPE_ARP, sys.modules[__name__])
