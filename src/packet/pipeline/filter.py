PERMIT=True
DISCARD=False

def identity_match(packet_ident, proto_ident):
    """Compares two identity lists to see if they match.
Every protocol identity in proto_ident must match those
in packet_ident sufficiently."""
    match = False
    for i in range(0, len(proto_ident)):
        if packet_ident[i] != proto_ident[i]
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
    if deny is None:
        deny = set()

    for packet in source:
        permit = policy
        for proto_ident in permit:
            if identity_match(packet.identity, ident):
                permit = True
        else:
            for proto_ident in discard:
                if identity_match(packet.identity, proto_ident):
                    permit = False
        if permit:
            yield packet
