import collections
import time

"""
common:
 - Abstract classes for packet capture file readers/writers.
 - Definition for the 'PacketInfo' named tuple
 - Functions for operating on the 'PacketInfo' named tuple.
"""

PacketInfo = collections.namedtuple("PacketInfo",
    ["timestamp", "nanosec", "caplen", "origlen"])


def print_packetinfo(packet_info):
    """Prints information in a PacketInfo tuple to stdout."""
    print("{0} ({1:06}μs) Original length: {2}".format(
        time.ctime(packet_info.timestamp), packet_info.nanosec / 1000, packet_info.origlen))


class PacketReader:
    """Abstract class for packet readers.
Implementatons must provide the 'read_packet' method."""

    def read_packet():
        """Abstract method read_packet.
Should return a tuple, consisting of the 'PacketInfo' tuple, and the data."""
        raise NotImplementedError("read_packet not implemented.")

    def close():
        """Abstract method close. Should close filesystem resources."""
        raise NotImplementedError("close not implemented.")


class PacketWriter:
    """Abstract class for packet writers.
Implementations must provide the 'write_packet' method."""

    def write_packet(packet_info, packet_data):
        """Abstact method write_packet
Should take two arguments, the 'PacketInfo' tuple, and the data."""
        raise NotImplementedError("write_packet not implemented.")

    def close():
        """Abstract method close. Should cleanup any filesystem resources."""
        raise NotImplementedError("close not implemented.")
