"""
filter: contains the filter function.
"""

KEEP = True
DISCARD = False


def identity_match(protocol_instances, prototypes):
    """
    Compares a packet's identity list (protocol instances) to a list of
    'prototypes'.
    Every prototype must match it's corresponding protocol instance.
    Prototypes are a (name, attrs) tuple.
    """
    prototype_iter = iter(prototypes)
    match = False
    for protocol_instance, prototype in zip(protocol_instances, prototype_iter):
        if protocol_instance.name is not prototype[0] or \
          not protocol_instance.match_attributes(prototype[1]):
            break
    else:
        # A short prototype list should match a more specific protocol identity,
        # but a short identity should not match a more specific prototype list.
        # This sees if the number of prototypes exceeds
        # the number of protocol_instances.
        try:
            next(prototype_iter)
        except StopIteration:
            match = True

    return match


# Any identity matching something in the keep set is kept.
# Any identity matching something in the discard set is discarded.
# Otherwise, the policy boolean is used.
def filter(source, keep=None, discard=None, policy=KEEP):
    """
    Selectively keeps or discards packets based on their identity.
    This pipeline assumes that packets have been identified prior to use.
    The keep and discard sets are collections of 'identities'
    Identities are lists of 'prototypes'.
    A prototype is a combination of a protocol name and a set of attributes.
    The name must match that of the corresponding protocol instance, and the
    match_attributes method of the corresponding protocol instance must
    return true when presented with the prototype attributes.
    """
    if keep is None:
        keep = set()
    if discard is None:
        discard = set()

    for packet in source:
        yield_packet = policy
        for prototypes in keep:
            if identity_match(packet.identity, prototypes):
                yield_packet = True
                break
        else:
            for prototypes in discard:
                if identity_match(packet.identity, prototypes):
                    yield_packet = False
                    break
        if yield_packet:
            yield packet
