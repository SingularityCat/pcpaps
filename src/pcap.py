import struct

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

class PcapFormatError(Exception):
    """Exception raised when a file format error occurs."""
    pass

class PcapReader:
    """PcapReader: reader for pcap files."""
    def __init__(self, fstream, magic=None):
        """Creates a PcapReader from an open stream.
Takes one mandatory and one optional argument,
 - fstream: The readable stream to use.
 - magic: The first four bytes of the file. If this is None, four bytes are read from the stream first."""

        self.stream = fstream

        # Magic number: [a1 b2 c3 d4] OR [a1 b2 3c 4d] if file has nanosecond resolution.
        # This is stored in the same endianess as the rest of the integer data in this file,
        # giving four possible values this could be.
        if magic == None:
            magic = self.stream.read(4)

        # Determine 
        if magic.startswith(b"\xa1\xb2"):
            # File is big-endian...
            global_header_struct = PCAP_BE_GLOB_HDR
            self.packet_header_struct = PCAP_BE_PKT_HDR

            if magic.endswith(b"\xc3\xd4"):
                # Regular (microsecond) big-endian pcap file
                pass
            elif magic.endswith(b"\x3c\x4d"):
                # Nanosecond big-endian pcap file
                pass
            else:
                raise PcapFormatError("Invalid magic {0}".format(magic))

        elif magic.endswith(b"\xb2\xa1"):
            # File is little-endian...
            global_header_struct = PCAP_LE_GLOB_HDR
            self.packet_header_struct = PCAP_LE_PKT_HDR

            if magic.startswith(b"\xd4\xc3"):
                # Regular (microsecond) little-endian pcap file
                pass
            elif magic.startswith(b"\xd4\xc3"):
                # Nanosecond little-endian pcap file
                pass
            else:
                raise PcapFormatError("Invalid magic {0}".format(magic))
        else:
            raise PcapFormatError("Invalid magic {0}".format(magic))
    
        # Read header
        global_header_data = self.stream.read(global_header_struct.size)
        self.version_major, self.version_minor, self.thiszone, self.sigfigs, self.snaplen, self.network = global_header_struct.unpack(global_header_data)

        # Store the start of the file, sans header.
        self.startpos = self.stream.tell()


    def read_packet(self, data=True):
        """Reads a packet record header, and optionally, it's data, from the stream."""
        packet_header_data = self.stream.read(self.packet_header_struct.size)
        # Test for EOF or truncation
        if packet_header_data == b"":
            #EOF
            return None
        elif 0 < len(packet_header_data) < self.packet_header_struct.size:
            # Truncation
            raise PcapFormatError("Truncated file")
            
        
        packet_header = self.packet_header_struct.unpack(packet_header_data)

        if data:
            packet_body = self.stream.read(packet_header[2])
        else:
            packet_body = None
            self.stream.seek(head[2], 1)
        return packet_header, packet_body
