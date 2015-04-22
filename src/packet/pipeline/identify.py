"""
identify: Contains the identify function.
"""

from .. identity import core as identity_core


def identify(source):
    """
    Returns each packet in the source, with the packet identity set.
    This generator will defer packets until their identity is complete.
    As a result, this generator can consume a lot of memory, up to the total
    number of packets produced by source.

    If the source is exhausted before a packet's identity is complete,
    the packets will then be returned regardless of status.
    """
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
        yield leftover
