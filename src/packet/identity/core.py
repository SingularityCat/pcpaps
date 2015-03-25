"""
core: root module of identification system
"""

ATTRIBUTE_WILDCARD = None

class ProtocolIdentity:
    __slots__ = {"name", "attributes", "offset"}
    def __init__(self, name, attrs, offset):
        self.name = name
        self.attributes = attrs
        self.offset = offset

    def __eq__(self, target):
        assert isinstance(target, ProtocolIdentity)
        if target.name == self.name:
            tattrs = target.attributes
            sattrs = self.attributes
            
            tkeys = set(tattrs.keys())
            skeys = set(sattrs.keys())
            if tkeys <= skeys:
                for key in tkeys & skeys:
                    if sattrs[key] != tattrs[key] and sattrs[key] is not None:
                        break
                else:
                    return True
            
            
        return False


def root_identify(packet, linktype):
    if linktype in registry:
        registry[linktype].identify(packet, 0)

def register(linktype, idfunc):
    registry[linktype] = idfunc

registry = {}
