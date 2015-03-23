import struct

from ..common import Packet
from .core import PacketReader, PacketWriter

"""
pcap: Contains classes for reading and writing to pcap files.
"""

# libpcap's global header
#
# typedef struct pcap_hdr_s
# {
#     guint32 magic_number;   /* magic number */
#     guint16 version_major;  /* major version number */
#     guint16 version_minor;  /* minor version number */
#     gint32  thiszone;       /* GMT to local correction */
#     guint32 sigfigs;        /* accuracy of timestamps */
#     guint32 snaplen;        /* max length of captured packets, in octets */
#     guint32 network;        /* data link type */
# } pcap_hdr_t;

# libpcap's record/packet header:
#
# typedef struct pcaprec_hdr_s
# {
#     guint32 ts_sec;         /* timestamp seconds */
#     guint32 ts_usec;        /* timestamp microseconds */
#     guint32 incl_len;       /* number of octets of packet saved in file */
#     guint32 orig_len;       /* actual length of packet */
# } pcaprec_hdr_t;

# Literal definitions for the possible valid permutations of the magic number.
PCAP_LE_REGULAR = b"\xd4\xc3\xb2\xa1"
PCAP_LE_NANOSEC = b"\x4d\x3c\xb2\xa1"
PCAP_BE_REGULAR = b"\xa1\xb2\xc3\xd4"
PCAP_BE_NANOSEC = b"\xa1\xb2\x3c\x4d"

# Struct objects for the above C structures in little/big endian forms.
# Note that the 'magic_number' field is omitted from the *_GLOB_HDR definitons.
PCAP_LE_GLOB_HDR = struct.Struct("<HHiIII")
PCAP_LE_PKT_HDR = struct.Struct("<IIII")
PCAP_BE_GLOB_HDR = struct.Struct(">HHiIII")
PCAP_BE_PKT_HDR = struct.Struct(">IIII")

# Major/minor versions of the pcap file format.
PCAP_MAJOR_VER = 2
PCAP_MINOR_VER = 4


# Magic number: [a1 b2 c3 d4] OR [a1 b2 3c 4d] if file has nanosecond
# resolution. This is stored in the same endianess as the rest of the
# integer data in this file, giving four possible values this could be.
def pcap_magic_resolve(magic):
    """Function that resolves pcap's magic number into an appropriate struct/scale.
Raises PcapFormatError on invalid magic."""
    if magic.startswith(b"\xa1\xb2"):
        # File is big-endian...
        global_header_struct = PCAP_BE_GLOB_HDR
        packet_header_struct = PCAP_BE_PKT_HDR
        if magic.endswith(b"\xc3\xd4"):
            # Regular (microsecond) big-endian pcap file
            timescale = 10**6
        elif magic.endswith(b"\x3c\x4d"):
            # Nanosecond big-endian pcap file
            timescale = 10**9
        else:
            raise PcapFormatError("Invalid magic {0}".format(magic))
    elif magic.endswith(b"\xb2\xa1"):
        # File is little-endian...
        global_header_struct = PCAP_LE_GLOB_HDR
        packet_header_struct = PCAP_LE_PKT_HDR

        if magic.startswith(b"\xd4\xc3"):
            # Regular (microsecond) little-endian pcap file
            timescale = 10**6
        elif magic.startswith(b"\xd4\xc3"):
            # Nanosecond little-endian pcap file
            timescale = 10**9
        else:
            raise PcapFormatError("Invalid magic {0}".format(magic))
    else:
        raise PcapFormatError("Invalid magic {0}".format(magic))

    return global_header_struct, packet_header_struct, timescale


class PcapFormatError(RuntimeError):
    """Exception raised when a file format error occurs."""
    pass


class PcapRangeError(RuntimeError):
    """Exception raised when a unrepresentable value is encountered."""
    pass


class PcapReader(PacketReader):
    """PcapReader: reader for pcap files."""
    def __init__(self, fstream, magic=None):
        """Creates a PcapReader from an open stream.
Takes one mandatory and one optional argument,
 - fstream: The readable stream to use.
 - magic: The first four bytes of the file.
   If this is None, four bytes are read from the stream first."""
        self.stream = fstream

        # Read magic number if not done so already.
        if magic is None:
            magic = self.stream.read(4)

        # Remember magic.
        self.magic = magic

        # Understand magic. This throws a PcapFormatError if incorrect.
        global_header_struct, self.packet_header_struct, self.timescale\
            = pcap_magic_resolve(self.magic)
        # Read header
        global_header_data = self.stream.read(global_header_struct.size)

        # Store header fields into attributes.
        self.version_major, self.version_minor,\
            self.thiszone,\
            self.sigfigs,\
            self.snaplen,\
            self.network = global_header_struct.unpack(global_header_data)

    def read_packet(self):
        """Reads a packet record header and it's data from the stream.
Returns a Packet object, or None on EOF"""
        packet_header_data = self.stream.read(self.packet_header_struct.size)
        # Test for EOF or truncation
        if packet_header_data == b"":
            # EOF
            return None
        elif 0 < len(packet_header_data) < self.packet_header_struct.size:
            # Truncation
            raise PcapFormatError("Stream truncated.")

        packet_header = self.packet_header_struct.unpack(packet_header_data)
        packet_data = self.stream.read(packet_header[2])

        # (unixtime, origlen, data)
        packet = Packet(
            packet_header[0] + self.thiszone + (packet_header[1] / self.timescale),
            packet_header[3],
            packet_data)

        return packet

    def close(self):
        """Closes the stream."""
        self.stream.close()


class PcapWriter(PacketWriter):
    """"""
    def __init__(self, stream, magic=PCAP_LE_REGULAR, thiszone=0, snaplen=65535, network=1):
        """Setup a new PcapWriter object, and write a global header to the stream."""
        self.stream = stream
        self.thiszone = thiszone
        self.snaplen = snaplen
        self.network = network

        # Understand magic. This throws a PcapFormatError if incorrect.
        global_header_struct, self.packet_header_struct, self.timescale\
            = pcap_magic_resolve(magic)

        self.stream.write(magic)
        self.stream.write(global_header_struct.pack(
            PCAP_MAJOR_VER, PCAP_MINOR_VER, 0, 0,
            self.snaplen, self.network))

    def write_packet(self, packet):
        """Writes a packet record header and data to the stream."""

        # Truncate packet.data to the snaplen limit, if needed.
        maxlen = min(self.snaplen, len(packet.data))

        # Build packet record header.
        packet_header = self.packet_header_struct.pack(
            int(packet.unixtime) - self.thiszone,
            round((packet.unixtime % 1.0) * self.timescale),
            maxlen, packet.origlen)

        self.stream.write(packet_header)
        self.stream.write(packet.data[:maxlen])

    def close(self):
        """Closes the stream."""
        self.stream.close()
