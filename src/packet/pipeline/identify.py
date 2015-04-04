from .. identity import core as identity_core
def identify(source):
    # Deferred packets go here.
    buf = []

    for packet in source:
        # Identify:
        identity_core.root_identify(packet)
        if not packet.identity.is_complete():
            buf.append(packet)
            continue

        if len(buf) > 0:
            while len(buf) > 0 and buf[0].identity.is_complete():
                yield buf.pop(0)
        else:
            yield packet

    for leftover in buf:
        yield buf
