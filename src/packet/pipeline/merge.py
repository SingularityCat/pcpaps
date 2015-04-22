"""
merge: contains the definition for the merge function.
"""

from .. import common


def merge(preaders, relative=True, offset=None):
    """
    Generator function that takes a list of packet sources and two parameters.
    If relative is true, then the time of the -first- packet from a source is
    subtracted from all packets from that source.
    If offset is not none, this value is added to the time of all packets,
    otherwise the average start time is used.
    Returns a generator that produces the next chronological packet on each iteration.
    """
    # Create a local copy of the 'preaders' argument
    # we don't want to modify the original.
    tails = preaders[:]
    heads = []

    # Create a list of 'heads',
    # packets in the start of each source, deleting empty sources.
    src_count = len(tails)
    i = 0
    while i < src_count:
        try:
            heads.append(next(tails[i]))
            i += 1
        except StopIteration:
            del tails[i]
            src_count -= 1

    # Create list of staring packet times.
    times = [pkt.unixtime for pkt in heads]

    # If no specific time offset is used, use the average start time.
    if offset is None:
        offset = sum(times) / len(times)

    # Create a list of computed offsets.
    offsets = [(-st if relative else 0) + offset for st in times]

    # Add all the computed offsets to the initial packets.
    for i in range(0, src_count):
        heads[i].unixtime += offsets[i]

    # While there are packet sources left...
    while src_count > 0:
        min_p = common.PACKET_MAXAGE
        # Find the index of the oldest packet.
        for j in range(0, src_count):
            if heads[j] <= min_p:
                min_p = heads[j]
                min_idx = j

        # Yield, returning the next chronoligcal packet.
        yield heads[min_idx]

        try:
            # Get the next packet from the source this packet came from.
            heads[min_idx] = next(tails[min_idx])
            # Calculate new time for the packet.
            heads[min_idx].unixtime += offsets[min_idx]
        except StopIteration:
            # This indicates there are no more packets in this source.
            del heads[min_idx]
            del tails[min_idx]
            del offsets[min_idx]
            src_count -= 1
