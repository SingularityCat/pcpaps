import sys
import struct

from .. import common

from . import core

# Ethernet frames have a fairly consistent format.
# A packet capture will typically contain the
# contents of a frame between the SFD (start of frame delimiter)
# and the CRC (cyclic redundancy check).

# There are a few standards dictating the structure of an ethernet frame,
#  - Ethernet II
#  - IEEE 802.3
#  - IEEE 802.1Q
#
# They all have a common layout and Ethernet II and IEEE 802.3.
# frames are almost the same, IEEE 802.1Q -adds- a field.
# They have the form:
# <sfd> <src mac> <dst mac> [<802.1Q hdr>] <ethertype/size> <payload> <crc>, or
# 6 bytes, 6 bytes, [4 bytes], 2 bytes, n bytes, 4 bytes.
# 
# The 4 byte field 1Q adds, consists of a 2-byte '0x8100' used to distinguish 1Q
# frames from Ethernet II/802.3 frames, and 2 bytes of information relating to VLANs.
#
# Additionally, there is a 802.1ad standard, which contains two 1Q headers.
# This one has '0x88A8' as it's identifier, and '0x8100' as it's next identifier.


# Definitions for a handful of ethertypes.
# These are the interesting ones, there are many more.
ETHERTYPE_IP4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_WOL = 0x0842
ETHERTYPE_IP6 = 0x86DD

# Not an ethertype per se, but...
ETHERTYPE_IEEE802_1Q = 0x8100
ETHERTYPE_IEEE802_1AD = 0x88A8

int16 = struct.Struct("!H")

def decompose(data):
    """Function that decomposes an ethernet frame."""
    # This stuff never changes.
    dmac = data[0:6]
    smac = data[6:12]

    # Tenative 'EtherType'
    ethertype = int16.unpack(data[12:14])[0]
    # Check for 1Q/1AD frames.
    if ethertype == ETHERTYPE_IEEE802_1Q:
        # skip 4 bytes to account for 1Q header.
        payload_offset = 18
        ethertype = int16.unpack(data[16:18])[0]
    elif ethertype == ETHERTYPE_IEEE802_1AD:
        # skip 8 bytes to account for 1AD headers.
        payload_offset = 22
        ethertype = int16.unpack(data[20:22])[0]
    else:
        payload_offset = 16
    
    return dmac, smac, ethertype, payload_offset

identifier = "eth"

def identify(packet, offset):
    dmac, smac, ethertype, next_offset = decompose(packet.data[offset:])
    attrs = {
        "dmac" : dmac,
        "smac" : smac,
        "ethertype" : ethertype,
    }
    
    packet.identity.append(core.ProtocolIdentity(identifier, attrs, offset))
    if ethertype in registry:
         registry[ethertype].identify(packet, next_offset)

def modify(packet):
    pass

def register(ethertype, module):
    registry[ethertype] = module

registry = {}

core.register(common.LINKTYPE_ETHERNET, sys.modules[__name__])
