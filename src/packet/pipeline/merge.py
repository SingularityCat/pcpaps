"""
merge: contains the definition for the merge function.
"""

from .. import common

def merge(preaders, relative=True, offset=None):
    """Generator function that takes a list of PacketReaders and some parameters.
If relative is true, then the time of the -first- packet from a reader is subtracted
from all packets from that reader.
If offset is not none, this value is added to the time of all packets, otherwise
the average start time is used.
Returns a generator that produces the next chronological packet on each iteration."""
    # Create a local copy of the 'preaders' argument - we don't want to modify the original.
    tails = preaders[:]
    # Create a list of 'heads' - packets in the start of each 'queue'.
    heads = [src.read_packet() for src in tails]

    queue_count = len(tails)

    # Delete empty queues (those with None as their head) from head/tail lists.
    i = 0
    while i < queue_count:
        if heads[i] is None:
            del heads[i]
            del tails[i]
            queue_count -= 1
            continue
        else:
            i += 1

    # Create list of staring packet times.
    times = [pkt.unixtime for pkt in heads]

    # If no specific time offset is used, use the average start time.
    if offset is None:
        offset = sum(times) / len(times)

    # Create a list of computed offsets.
    offsets = [(-st if relative else 0) + offset for st in times]

    # Add all the computed offsets to the initial packets.
    for i in range(0, queue_count):
        heads[i].unixtime += offsets[i]

    # While there are packet queues left...
    while queue_count > 0:
        min_p = common.PACKET_MAXAGE
        # Find the index of the oldest packet.
        for j in range(0, queue_count):
            if heads[j] <= min_p:
                min_p = heads[j]
                min_idx = j

        # Yield, returning the next chronoligcal packet.
        yield heads[min_idx]

        # Get the next packet from the queue this packet came from.
        heads[min_idx] = tails[min_idx].read_packet()

        # Check if read_packet returned None. This indicates there are no more packets in this reader.
        if heads[min_idx] is None:
            # Delete the queue if it's empty.
            del heads[min_idx]
            del tails[min_idx]
            del offsets[min_idx]
            queue_count -= 1
        else:
            # Otherwise calculate new time for the packet.
            heads[min_idx].unixtime += offsets[min_idx]
