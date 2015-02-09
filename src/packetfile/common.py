import collections
import math
import time

"""
common:
 - Definition for the 'Packet' named tuple
 - Functions for operating on the 'Packet' named tuple.
 - Abstract classes for packet capture file readers/writers.
"""

Packet = collections.namedtuple("Packet", ["unixtime", "origlen", "data"])
Packet.__doc___ = """\
Named tuple consisting of three fields,
 - unixtime: Floating point number, time in seconds since 1st Jan, 1970.
 - origlen: Original length of the 'data' field.
 - data: Packet data."""


def print_packetinfo(packet):
    """Prints information in a Packet tuple to stdout."""
    print("{0} ({1}μs) Original length: {2}, Captured length: {3}".format(
        time.ctime(packet.unixtime),
        math.fmod(packet.unixtime, 1.0) * 10**6,
        packet.origlen, len(packet.data)))


class PacketReader:
    """Abstract class for packet readers.
Implementatons must provide the 'read_packet' method."""

    def read_packet():
        """Abstract method read_packet.
Should return a tuple, consisting of the 'Packet' tuple."""
        raise NotImplementedError("read_packet not implemented.")

    def close():
        """Abstract method close. Should close filesystem resources."""
        raise NotImplementedError("close not implemented.")


class PacketWriter:
    """Abstract class for packet writers.
Implementations must provide the 'write_packet' method."""

    def write_packet(packet):
        """Abstact method write_packet
Should take one argument, the 'Packet' tuple."""
        raise NotImplementedError("write_packet not implemented.")

    def close():
        """Abstract method close. Should cleanup any filesystem resources."""
        raise NotImplementedError("close not implemented.")
