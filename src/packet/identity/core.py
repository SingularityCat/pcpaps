import enum
import struct

"""
core: root module of identification system
Contains class definition for a 'Stream'.
Contains abstract class definition for Protocol and CarrierProtocol.
"""

class AddrType(enum.Enum):
    IP4 = "ip4"
    IP6 = "ip6"
    MAC = "mac"


class Stream:
    """This class represents a 'stream'. """
    pass


ATTRIBUTE_WILDCARD = None


class Protocol:
    """This class represents a protocol.
An instance of a protocol has a set of 'attributes', such as
fields in the header of a packet. An attribute is a smaller piece
of variable data in a protocol, for instance, a sender's IP address
is an attribute of an IP header. A protocol also has a 'next' and 'prev' - 
child and parent protocols, respectively.
All protocol instances have a 'completed' flag."""

    name = None
    __slots__ = {"data", "next", "prev", "completed"}


    def __init__(self, data, prev):
        """Constructor for protocol instances. """
        self.data = data
        self.next = None
        self.prev = prev
        self.completed = True


    def __iter__(self):
        """Generator method for accessing this/child protocol instances."""
        current = self
        while current is not None:
            yield current
            current = current.next


    def is_complete(self):
        """Returns True if this and all child protocols are complete."""
        if not self.completed:
            return False

        if self.next is not None:
            return self.next.is_complete()

        return True


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


    def replace_hosts(self, hostmap):
        """This method should replace instances of host identification,
Namely IP addresses and MAC addresses. This operation should propagate to child
protocols. The default implementation does nothing other then this propogation
and should suffice for protocols without any kind of host identification."""
        if self.next is not None:
            self.next.replace_hosts(hostmap)


    def recalculate_checksums(self):
        """This method should recalculate any kind of checksum used by this
protocol, after any 'child' checksums have been recomputed.
That is to say, the recalculation should propagate up, from the highest-level
protocol to the lowest. The default implementation does nothing other then
this propogation and should suffice for protocols without validation."""
        if self.next is not None:
            self.next.recalculate_checksums()


    @staticmethod
    def reset_state():
        """This static method should restore the initial state to any kind of
state tracker this class uses. This means, any data held by the class
to associate multiple bits of data (think IP fragmentation or TCP) should be
forgotten. The default implementation does nothing and should suffice for simple
protocols."""
        return


    @staticmethod
    def interpret_packet(data, parent):
        """Abstract static method interpret_packet.
This takes two arguments, a 'parent' protocol instance (which can be none) and data.
This should create an instance of it's class, determine the next (if any)
protocol to interpret (setting the next field), then return said instance."""
        # Example:
        # instance = Protocol(data, parent)
        # ...
        # other_protocol.intepret_packet(data[next_offset:], instance)
        # return instance
        raise NotImplementedError("interpret_packet not implemented.")


    @staticmethod
    def interpret_stream(stream, parent):
        """Abstract static method interpret_stream.
Like interpret_packet, this takes two arguments, a 'parent' protocol instance
(which can be none) and a 'stream' object. This method should create an
instance of it's class, determine the next (if any) protocol to interpret,
(setting the next field), then return said instance."""
        raise NotImplementedError("interpret_stream not implemented.")


    @staticmethod
    def build_attributes(attrstr):
        """Abstract static method build_attributes.
Should return a dict of attributes based on a human-readable expression string."""
        raise NotImplementedError("build_attributes not implemented.")


class CarrierProtocol(Protocol):
    """This class represents a protocol that carries other protocols.
In addition to the Protocol methods, a CarrierProtocol needs to implement
the get_route and get_route_reciprocal methods."""


    def get_route():
        """Abstract method returning a hashable object that represents
the 'route' (the destination, source and direction) a carrier protocol would
direct a packet."""
        raise NotImplementedError("get_route not implemented.")


    def get_route_reciprocal():
        """Abstract method returning a hashable object not unlike the above,
that returns the opposite route.
E.g. if get_route returned A -> B, this should return B -> A."""
        raise NotImplementedError("get_route_reciprocal not implemented.")


class Unknown(Protocol):
    name = "unknown"


    def get_attributes(self):
        return {}


    def set_attributes(self):
        return


    def match_attributes(self, attrs):
        return True


    @staticmethod
    def interpret_packet(data, parent):
        return Unknown(data, parent)


    @staticmethod
    def interpret_stream(stream, parent):
        return Unknown(stream, parent)


    @staticmethod
    def build_attributes(attrstr):
        return {}


# Utility functions useful for protocol classes.

uint16 = struct.Struct("!H")


def uint16pack(i):
    """Converts a 16-bit int into bytes (big endian)"""
    return uint16.pack(i)


def uint16unpack(b):
    """Converts bytes into a 16-bit int (big endian)"""
    return uint16.unpack(b)[0]


# Functions dealing with identification,
# protocol registration and linktype registration.

def root_identify(packet):
    """Identify a packet.
This function may have side effects.
This function will set the packet.identity field to a protocol instance, or None.
This function will return packets with an incomplete identity. Packets with an
incomplete identity can and will have their identities updated whenever a protocol
class deems suitable."""
    if packet.linktype in linktype_registry:
        protocol = lookup_protocol(linktype_registry[packet.linktype])
        packet.identity = protocol.interpret_packet(memoryview(packet.data), None)


def register_linktype(protoname, linktype):
    """This function adds a protocol to the linktype registry.
The linktype registry determines what protocol to first interpret a packet as.
Protocols in this registry would correspond to the valus of linktypes defined in
packet.common.LinkType"""
    linktype_registry[linktype] = protoname


def register_protocol(protocol):
    """This function adds a protocol to the protocol registry.
The protocol registry maps a protocol's name to it's class."""
    protocol_registry[protocol.name] = protocol


def lookup_protocol(protoname):
    """This finds a protocol class by it's name.
All protocol classes should be referred to by name. This allows them to be
overridden by simply registering a different class with the same name."""
    if protoname in protocol_registry:
        protocol = protocol_registry[protoname]
    else:
        protocol = Unknown
    return protocol

linktype_registry = {}
protocol_registry = {}
