"""
core: root module of identification system
Contains class definition for ProtocolIdentity.
"""

ATTRIBUTE_WILDCARD = None

class ProtocolIdentity:
    """A 'protocol identity'.
This class represents a piece of data conforming to a protocol.
An example of a protocol identitiy would be a IP header.
It stores these identities in terms of 'attributes' in a dictionary.
An attribute is a smaller piece of variable data in a protocol, for
instance, an sender's IP address is a attribute of an IP header.
It also stores a field called 'offset', which is how far into the
packet the header of this protocol is. This field does not make sense
for all protocols, or prototypes."""
    __slots__ = {"name", "attributes", "offset"}
    def __init__(self, name, attrs, offset):
        """Constructor for 'protocol identities'. """
        self.name = name
        self.attributes = attrs
        self.offset = offset

    def match_protocol(self, target):
        """Returns true if two protocol identities share the
same protocol identifier."""
        assert isinstance(target, ProtocolIdentity)
        return self.name == target.name

    def match(self, target):
        """Tests wether this ProtocolIdentity matches another.
This is not commutative - all of the target keys MUST be in
this ProtocolIdentity's keys. Additionally, if the target's key is
equal to None, it is treated as a wildcard and matches."""
        assert isinstance(target, ProtocolIdentity)
        if target.name == self.name:
            # More convienient names.
            tattrs = target.attributes
            sattrs = self.attributes
            
            tkeys = set(tattrs.keys())
            skeys = set(sattrs.keys())
            if tkeys <= skeys:
                for key in tkeys & skeys:
                    if sattrs[key] != tattrs[key] and \
                        tattrs[key] is not ATTRIBUTE_WILDCARD:
                        break
                else:
                    return True
        return False

    def __eq__(self, target):
        return self.match(target)

    def __ne__(self, target):
        return not self.match(target)

def root_identify(packet, linktype):
    if linktype in registry:
        registry[linktype].identify(packet, 0)

def register(linktype, idfunc):
    registry[linktype] = idfunc

registry = {}
