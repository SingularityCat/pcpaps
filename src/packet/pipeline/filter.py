KEEP = True
DISCARD = False

def identity_match(protocol_instances, prototypes):
    """Compares a packet's identity list (protocol instances) to a list of
'prototypes'. Every prototype must match it's corresponding protocol instance.
Prototypes are a (name, attrs) tuple."""
    match = False
    for protocol_instance, prototype in zip(protocol_instances, prototypes):
        if not protocol_instance.name is prototype[0] or \
            not  protocol_instance.match_attributes(prototype[1]):
            break
    else:
        match = True
    return match


# Any identity matching something in the keep set is kept.
# Any identity matching something in the discard set is discarded.
# Otherwise, the policy boolean is used.
def filter(source, keep=None, discard=None, policy=KEEP):
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
