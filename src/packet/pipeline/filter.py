PERMIT=True
DISCARD=False

def identity_match(protocol_instances, prototypes):
    """Compares a packet's identity list (protocol instances) to a list of
'prototypes'. Every prototype must match it's corresponding protocol instance.
Prototypes are a (name, attrs) tuple."""
    match = False
    idx_range = min(len(protocol_instances), len(prototypes))
    for i in range(0, idx_range):
        if not protocol_instances[i].name is prototypes[i][0] or \
            not  protocol_instances[i].match_attributes(prototypes[i][1]):
            break
    else:
        match = True
    return match


# Any identity matching something in the permit set is permitted.
# Any identity matching something in the discard set is discarded.
# Otherwise, the policy boolean is used.
def filter(source, permit=None, discard=None, policy=PERMIT):
    if permit is None:
        permit = set()
    if discard is None:
        discard = set()

    for packet in source:
        yield_packet = policy
        for prototypes in permit:
            if identity_match(packet.identity, prototypes):
                yield_packet = True
        else:
            for prototypes in discard:
                if identity_match(packet.identity, prototypes):
                    yield_packet = False
        if yield_packet:
            yield packet
