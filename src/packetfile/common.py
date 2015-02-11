import collections
import math
import time

"""
common:
 - Definition for the 'Packet' named tuple
 - Functions for operating on the 'Packet' named tuple.
 - Abstract classes for packet capture file readers/writers.
"""

class Packet(collections.namedtuple("Packet", ["unixtime", "origlen", "data"])):
    """Named tuple consisting of three fields,
 - unixtime: Floating point number, time in seconds since 1st Jan, 1970.
 - origlen: Original length of the 'data' field.
 - data: Packet data.

Comparison operator methods and the length method are implemented.
Comparisons work on the value of 'unixtime', so a < b means a is older then b.
The length is 'origlen', so len(a) < len(b) means a was shorter then b."""

    # Implement comprison operations based on 'unixtime', such that:
    # a < b means a is older then b.
    def __lt__(self, other):
        return self.unixtime < other.unixtime

    def __le__(self, other):
        return self.unixtime <= other.unixtime

    def __eq__(self, other):
        return self.unixtime == other.unixtime

    def __ne__(self, other):
        return self.unixtime != other.unixtime

    def __gt__(self, other):
        return self.unixtime > other.unixtime

    def __ge__(self, other):
        return self.unixtime >= other.unixtime

    # Implement length func based on 'origlen', such that:
    # len(a) < len(b) means a has an original length shorter then b.
    def __len__(self):
        return self.origlen


def print_packetinfo(packet):
    """Prints information in a Packet tuple to stdout."""
    print("{0} ({1}μs) Original length: {2}, Captured length: {3}".format(
        time.ctime(packet.unixtime),
        math.fmod(packet.unixtime, 1.0) * 10**6,
        packet.origlen, len(packet.data)))


class PacketReader:
    """Abstract class for packet readers.
Implementatons must provide the 'read_packet' method.
This class implements the __next__ method based on read_packet()"""

    def __iter__(self):
        """This makes the object an iterable.
A 'self iterable' as it simply returns self."""
        return self

    def __next__(self):
        """Iterator protocol interface."""
        pkt = self.read_packet()
        if pkt is None:
            raise StopIteration
        
        return pkt

    def read_packet(self):
        """Abstract method read_packet.
Should return the 'Packet' tuple, or None if there are no packets left."""
        raise NotImplementedError("read_packet not implemented.")

    def close(self):
        """Abstract method close. Should close filesystem resources."""
        raise NotImplementedError("close not implemented.")


class PacketWriter:
    """Abstract class for packet writers.
Implementations must provide the 'write_packet' method."""

    def write_packet(self, packet):
        """Abstact method write_packet
Should take one argument, the 'Packet' tuple."""
        raise NotImplementedError("write_packet not implemented.")

    def close(self):
        """Abstract method close. Should cleanup any filesystem resources."""
        raise NotImplementedError("close not implemented.")
