"""
core: root module of identification system
Contains abstract class definition for Protocol and CarrierProtocol.
"""

ATTRIBUTE_WILDCARD = None


class Protocol:
    """This class represents a protocol.
An instance of a protocol has a set of 'attributes', such as
fields in the header of a packet. An attribute is a smaller piece
of variable data in a protocol, for instance, a sender's IP address
is an attribute of an IP header. It also stores a field called
'offset', which is how far into the packet the header of this
protocol is. This field does not make sense
for all protocols."""

    name = None
    __slots__ = {"packet", "offset"}


    def __init__(self, packet, offset):
        """Constructor for protocol instances. """
        self.packet = packet
        self.offset = offset

        self.packet.identity.append(self)


    def get_attributes(self):
        """Abstract method get_attributes.
Should return a dict of useful attributes."""
        raise NotImplementedError("get_attributes not implemented.")


    def set_attributes(self, attrs):
        """Abstract method set_attributes.
Should accept a dict of attributes and update data accordingly."""
        raise NotImplementedError("set_attributes not implemented.")


    def match_attributes(self, tattrs):
        """Tests wether this ProtocolIdentity matches a set of attributes.
This is the default implementation and compares attributes of this
instance (from get_attributes) to the provided attributes (tattrs).
This is not commutative - all of the target keys MUST be in
this ProtocolIdentity's keys. Additionally, if the target's key is
equal to None, it is treated as a wildcard and matches."""
        # Retrieve attributes.
        sattrs = self.get_attributes()
            
        tkeys = set(tattrs.keys())
        skeys = set(sattrs.keys())

        # Check if tkeys is a weak subset of skeys.
        if tkeys <= skeys:
            for key in tkeys & skeys:
                # Check for mismatch.
                if sattrs[key] != tattrs[key] and \
                    tattrs[key] is not ATTRIBUTE_WILDCARD:
                    break
            else:
                # If loop did not find mismatches...
                return True
        # In all other cases...
        return False


    @staticmethod
    def interpret_packet(packet, offset):
        """Abstract static method interpret_packet.
This should modify it's argument, packet, adding an instance
of it's class and determining the next (if any) protocol to interpret."""
        # Example:
        # instance = Protocol(packet, offset)
        # attrs = instance.get_attributes()
        # ...
        # OtherProtocol.intepret_packet(packet, next_offset)
        raise NotImplementedError("interpret_packet not implemented.")


    @staticmethod
    def build_attributes(attrstr):
        """Abstract static method build_attributes.
Should return a dict of attributes based on a human-readable expression string."""
        raise NotImplementedError("build_attributes not implemented.")


    def __eq__(self, target):
        return self.match_attributes(target)


    def __ne__(self, target):
        return not self.match_attributes(target)


class Unknown(Protocol):
    name = "unknown"


    def get_attributes(self):
        return {}


    def set_attributes(self):
        return    


    def match_attributes(self, attrs):
        return False


    @staticmethod
    def interpret_packet(packet, offset):
        instance = Unknown(packet, offset)


    @staticmethod
    def build_attributes(attrstr):
        return {}


def root_identify(packet):
    """"""
    if packet.linktype in linktype_registry:
        protocol = linktype_registry[packet.linktype]
        protocol_registry[protocol].interpret_packet(packet, 0)


def register_linktype(protoname, linktype):
    """This function adds a protocol to the linktype registry.
The linktype registry determines what protocol to first interpret a packet as.
Protocols in this registry would correspond to the linktypes defined in packet.common"""
    linktype_registry[linktype] = protoname


def register_protocol(protocol):
    """This function adds a protocol to the protocol registry.
The protocol registry maps a protocol's name to it's class."""
    protocol_registry[protocol.name] = protocol


def lookup_protocol(protoname):
    if protoname in protocol_registry:
        protocol = protocol_registry[protoname]
    else:
        protocol = Unknown
    return protocol

linktype_registry = {}
protocol_registry = {}
