
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

# Struct format strings for the above C structures in little/big endian forms.
# Note that the 'magic_number' field is omitted from the *_GLOB_HDR strings.
PCAP_LE_GLOB_HDR = "<H<H<i<I<I<I"
PCAP_LE_PKT_HDR = "<I<I<I<I"
PCAP_BE_GLOB_HDR = ">H>H>i>I>I>I"
PCAP_BE_PKT_HDR = ">I>I>I>I"

class PcapReader:
    def __init__(self, fstream, magic=None):
        """Creates a PcapReader from an open stream.
Takes one mandatory and one optional argument,
 - fstream: The readable stream to use.
 - magic: The first four bytes of the file. If this is specified, """

        self.stream = fstream

        # Magic number: [a1 b2 c3 d4] OR [a1 b2 3c 4d] if file has nanosecond resolution.
        # This is stored in the same endianess as the rest of the integer data in this file,
        # giving four possible values this could be.
        if magic = None:
            magic = self.stream.read(4)

        # Store the start of the file, sans magic number.
        self.startpos = self.stream.tell()

        if magic.startswith(b"\xa1")
            
    
def pcap_read_packet(self, data=True):
    """Reads a packet record header, and optionally, it's data, from a file stream."""
    head = pcap_read_packet_header(stream)
    if data:
        body = stream.read(head[2])
    else
        body = None
        stream.seek(head[2], 1)
    return head, body

def pcap_read_packet_header(self):
    """Reads a packet record header, returning a 4-tuple consisting of the """

