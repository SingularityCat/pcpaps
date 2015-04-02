from .. import common

from . import core
from .core import uint16pack, uint16unpack

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
# The 4 byte field 1Q adds, consists of a 2-byte '0x8100' used to distinguish
# 1Q frames from Ethernet II/802.3 frames, and 2 bytes of information relating
# to VLANs. Additionally, there is a 802.1ad standard, which contains two 1Q
# headers. This one has '0x88A8' as it's identifier, and '0x8100' as it's next
# identifier.

# This means the size of an ethernet frame header:
#   6 + [4] + [4] + 2 = 8 .. 16

# Definitions for a handful of ethertypes.
# These are the interesting ones, there are many more.
ETHERTYPE_IP4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_WOL = 0x0842
ETHERTYPE_IP6 = 0x86DD

# Not an ethertype per se, but...
ETHERTYPE_IEEE802_1Q = 0x8100
ETHERTYPE_IEEE802_1AD = 0x88A8


def find_ethertype_offset(data):
    """Finds the offset of the true ethertype of a frame."""
    # Tenative 'EtherType'
    ethertype = uint16unpack(data[12:14])
    # Check for 1Q/1AD frames.
    if ethertype == ETHERTYPE_IEEE802_1Q:
        # skip 4 bytes to account for 1Q header.
        offset = 16
    elif ethertype == ETHERTYPE_IEEE802_1AD:
        # skip 8 bytes to account for 1A/D headers.
        offset = 20
    else:
        offset = 12

    return offset


class Ethernet(core.CarrierProtocol):
    """Class representing the Ethernet II (IEEE 802.3/1Q/1AD) protocol."""
    name = "eth"
    __slots__ = {"_dmac", "_smac", "_ethertype", "payload_offset"}

    
    def __init__(self, packet, offset):
        """Constructor. Takes the packet and offset arguments.
Calculates offsets as it's only real action."""
        super().__init__(packet, offset)
        self._calculate_offsets()


    def _calculate_offsets(self):
        """Calculates offsets of all the fields and the payload."""
        self._dmac = slice(self.offset+0, self.offset+6)
        self._smac = slice(self.offset+6, self.offset+12)

        etype_offset = find_ethertype_offset(
            self.packet.data[self.offset:self.offset+16]
            )
        self._ethertype = slice(etype_offset, etype_offset+2)

        self.payload_offset = etype_offset + 2


    def get_route(self):
        """Returns the route of this ethernet header, as a 12-byte string."""
        return bytes(
            self.packet.data[self._dmac] + self.packet.data[self._smac]
        )


    def get_route_reciprocal(self):
        """Returns the reciprocal route of this ethernet header."""
        return bytes(
            self.packet.data[self._smac] + self.packet.data[self._dmac]
        )


    def get_attributes(self):
        """Returns the fields in this packet as a attribute dict."""
        dmac = self.packet.data[self._dmac]
        smac = self.packet.data[self._smac]
        ethertype = uint16unpack(self.packet.data[self._ethertype])
        return {
            "dmac" : dmac,
            "smac" : smac,
            "ethertype" : ethertype,
        }


    def set_attributes(self, attrs):
        """Updates the fields in this header to represent the contents
of an attribute dict."""
        # Get updated values
        if "dmac" in attrs:
            self.packet.data[self._dmac] = attrs["dmac"]

        if "smac" in attrs:
            self.packet.data[self._smac] = attrs["smac"]

        if "ethertype" in attrs:
            new_ethertype = attrs["ethertype"]
            # We don't support adding 1Q/1AD headers at the moment.
            if new_ethertype != ETHERTYPE_IEEE802_1Q and \
                new_ethertype != ETHERTYPE_IEEE802_1AD:
                self.packet.data[self._ethertype] = uint16pack(new_ethertype)

    @staticmethod
    def interpret_packet(packet, offset):
        """Creates a protocol instance and determines the next protocol to use.
This makes use of a registry of ethertype -> protocol names, updated with
the 'register_ethertype' function in this module."""
        instance = Ethernet(packet, offset)
        attrs = instance.get_attributes()
        ethertype = attrs["ethertype"]
        if ethertype in ethertype_registry:
            protoname = ethertype_registry[ethertype]
            protocol = core.lookup_protocol(protoname)

            protocol.interpret_packet(packet, instance.payload_offset)


    # Ethernet prototype attribute string format:
    # <attr> = <key> "=" <value>
    # <attrstr> = <attr> | <attr> ";" <attrstr>
    #
    # Attributes are seperated by semicolons,
    # which contain colon-seperated key-value pairs.
    # Valid keys are "dmac", "smac" and "ethertype" (or "len")
    @staticmethod
    def build_attributes(attrstr):
        """Creates a set of attributes from an attribute string."""
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

        return attrdict


def register_ethertype(protocol, ethertype):
    """Associates a protocol name with an ethertype."""
    ethertype_registry[ethertype] = protocol

ethertype_registry = {}

# Register the protocol, and as a linktype handler.
core.register_protocol(Ethernet)
core.register_linktype(Ethernet.name, common.LINKTYPE_ETHERNET)
