import collections
import math
import time

"""
common:
 - Definition for the 'Packet' named tuple
 - Functions for operating on the 'Packet' named tuple.
 - Functions for converting a ip4/ip6/mac address to string form and back.
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

    # Tuples are immutable, so 'modifications' are done by constructing a new
    # tuple to replace the old one. This method creates a duplicate tuple with
    # the option to set new fields.
    def dup(self, unixtime=None, origlen=None, data=None):
        """Create a duplicate Packet, with potentially different fields.
Returns the new tuple."""
        return Packet(
                self.unixtime if unixtime is None else unixtime,
                self.origlen if origlen is None else origlen,
                self.data if data is None else data
            )


PACKET_MINAGE = Packet(float("-inf"), 0, b"")
PACKET_MAXAGE = Packet(float("+inf"), 0, b"")


def print_packetinfo(packet):
    """Prints information in a Packet tuple to stdout."""
    print("{0} ({1}μs) Original length: {2}, Captured length: {3}".format(
        time.ctime(packet.unixtime),
        math.fmod(packet.unixtime, 1.0) * 10**6,
        packet.origlen, len(packet.data)))


def mac_str2bin(macs):
    """Converts a MAC address in string representation (six hex numbers,
delimited by colons) to a big-endian byte representation.
Returns None on a format error."""

    try:
        octets = [int(byte, 16) for byte in macs.split(":")]

        if len(octets) != 6:
            return None

        return bytes(octets)

    except ValueError:
        return None


def mac_bin2str(macb):
    """Converts a MAC address in big-endian byte form to a
string form not unlike the one accepted by the function above.
Returns None on a format error."""

    if len(macb) != 6:
        return None

    return ":".join("{0:02x}".format(byte) for byte in macb)


def ip4_str2bin(ip4s):
    """Converts a IPv4 address in dotted octet string form to a big-endian
byte representation.
Returns None on a format error."""
    try:
        octets = [int(byte) for byte in ip4s.split(".")]

        # Support short form, ie: 127.1 == 127.0.0.1
        if len(octets) > 4 or len(octets) < 2:
            return None

        lastoct = octets.pop()
        return bytes(octets + [0]*(3 - len(octets)) + [lastoct])
    except ValueError:
        return None


def ip4_bin2str(ip4b):
    """Converts a IPv4 address in big-endian byte form to a
string form not unlike the one accepted by the function above.
Returns None on a format error."""
    
    if len(ip4b) != 4:
        return None

    return ".".join("{0}".format(byte) for byte in ip4b)


def ip6_str2bin(ip6s):
    """Converts a IPv6 address in RFC-5952 format to a big-endian
byte representation.
Returns None on a format error."""
    # Expands a possibly compressed string representation of a byte pair to two bytes.
    expand = lambda s: divmod(int(s, 16), 256)

    try:
        # Check if the string contains the zero-compressed section.
        # This can only appear once, RFC 595 section 2.2.
        if "::" in ip6s:
            ip6i_start, ip6i_end = ip6s.split("::")
        
            ip6i_start = [expand(pair) for pair in ip6s_start.split(":")]
            ip6i_end = [expand(pair) for pair in ip6s_end.split(":")]
            ip6i = ip6i_start + [0]*(16 - (len(ip6i_start) + len(ip6i_end))) + ip6i_end
        else:
            ip6i = [expand(pair) for pair in ip6s.split(":")]

        return bytes(ip6i)
    except ValueError:
        return None


def ip6_bin2str(ip6b):
    """Converts a IPv6 address in big-endian byte form to a
string form not unlike the one accepted by the function above.
Returns None on a format error."""
    if len(ip6b) != 16:
        return None

    return ":".join
