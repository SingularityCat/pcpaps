import collections
import math
import time

"""
common:
 - Definition for the 'Packet' named tuple
 - Functions for operating on the 'Packet' named tuple.
Contains two constants, PACKET_MINAGE and PACKET_MAXAGE, two
psuedopackets being older then or newer then all other packets, respectively.
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


PACKET_MINAGE = Packet(float("-inf"), 0, b"")
PACKET_MAXAGE = Packet(float("+inf"), 0, b"")


def print_packetinfo(packet):
    """Prints information in a Packet tuple to stdout."""
    print("{0} ({1}μs) Original length: {2}, Captured length: {3}".format(
        time.ctime(packet.unixtime),
        math.fmod(packet.unixtime, 1.0) * 10**6,
        packet.origlen, len(packet.data)))


