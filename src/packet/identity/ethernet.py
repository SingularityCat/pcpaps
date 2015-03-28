import sys
import struct

from .. import common

from . import core

identifier = "eth"

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
# 1 byte, 6 bytes, 6 bytes, [4 bytes], 2 bytes, n bytes, 4 bytes.
#
# It seems that packet captures generally omit the sfd and crc.
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


def find_ethertype_offset(data):
    """Finds the offset of the true ethertype of a frame."""
    # Tenative 'EtherType'
    ethertype = int16.unpack(data[12:14])[0]
    # Check for 1Q/1AD frames.
    if ethertype == ETHERTYPE_IEEE802_1Q:
        # skip 4 bytes to account for 1Q header.
        offset = 16
    elif ethertype == ETHERTYPE_IEEE802_1AD:
        # skip 8 bytes to account for 1AD headers.
        offset = 20
    else:
        offset = 12

    return offset

def decompose(data):
    """Function that decomposes an ethernet frame.
Returns the destination mac, source mac, ethertype and the payload offset."""
    # This stuff never changes.
    dmac = data[0:6]
    smac = data[6:12]

    # EtherType Offset and PayLoad Offset
    eto = find_ethertype_offset(data)
    plo = eto + 2

    ethertype = int16.unpack(data[eto:plo])[0]

    return dmac, smac, ethertype, plo


def identify(packet, offset):
    """Extracts 'attributes' (source/destination MAC address etc...)
from an ethernet frame header at a given offset in a Packet,
creates an appropriate ProtocolIdentity label and adds it to
the Packet's identity."""
    dmac, smac, ethertype, next_offset = decompose(packet.data[offset:])
    attrs = {
        "dmac" : dmac,
        "smac" : smac,
        "ethertype" : ethertype,
    }
    
    # Create and add identity label.
    packet.identity.append(core.ProtocolIdentity(identifier, attrs, offset))

    # Call next identify function with the payload offset.
    if ethertype in registry:
         registry[ethertype].identify(packet, next_offset)


# Ethernet prototype attribute string format:
# <attr> = <key> "=" <value>
# <attrstr> = <attr> | <attr> ";" <attrstr>
#
# Attributes are seperated by semicolons, which contain colon-seperated key-value pairs.
# Valid keys are "dmac", "smac" and "ethertype" (or "len")
def prototype(attrstr):
    """Creates a ProtocolIdentity label from an 'attribute string'."""
    attrdict = {}

    attrs = attrstr.split(";")
    for attr in attrs:
        try:
            # Split into kvp.
            k, v = attr.split("=")

            if k == "dmac" or k == "smac":
                mac = common.mac_str2bin(v)
                # Check if mac is valid.
                if mac is not None:
                    attrdict[k] = mac
            elif k == "ethertype" or k == "len":
                ethertype = common.parse_int(v)
                # Check if etype is valid
                if ethertype is not None:
                    attrdict["ethertype"] = ethertype
        except ValueError:
            # Skip malformed attributes.
            pass
            
    return core.ProtocolIdentity(identifier, attrdict, None)


def modify(packet, ididx, prototype):
    """Alter an ethernet frame header to match a prototype."""
    try:
        # Get the current ProtocolIdentity.
        identity = packet.identity[ididx]
        # Simple sanity check:
        assert identity.name == prototype.name
    except (IndexError, AssertionError):
        # Something is wrong.
        return
    
    dmac, smac, ethertype, payload_offset = \
        decompose(packet.data[identity.offset:])

    # Get updated values
    if "dmac" in prototype.attributes:
        dmac = prototype.attributes["dmac"]

    if "smac" in prototype.attributes:
        dmac = prototype.attributes["smac"]

    identity.attributes.update(prototype.attributes)

    if "ethertype" in prototype.attributes:
        new_ethertype = prototype.attributes["ethertype"]
        # We don't support adding 1Q/1AD headers at the moment.
        if new_ethertype != ETHERTYPE_IEEE802_1Q and \
            new_ethertype != ETHERTYPE_IEEE802_1AD:
            ethertype = new_ethertype
            identity.attributes["ethertype"] = new_ethertype

    # Extract existing 1Q/1AD headers, if any.
    opt = packet.data[12:payload_offset - 2]
    # Rebuild the header:
    hdr = dmac + smac + opt + ethertype
    packet.data = packet.data[:identity.offset] + hdr + packet.data[payload_offset:]

def register(ethertype, module):
    registry[ethertype] = module

registry = {}

core.register(common.LINKTYPE_ETHERNET, sys.modules[__name__])
