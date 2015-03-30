import collections
import math
import time

"""
common:
 - Definition for the 'Packet' class
 - Functions for operating on the 'Packet' class.
 - Functions for handling generic user input, i.e. parse_int.
 - Functions for converting a ip4/ip6/mac address to string form and back.
Contains two constants, PACKET_MINAGE and PACKET_MAXAGE, two
psuedopackets being older then or newer then all other packets, respectively.
"""

class Packet:
    """Class consisting of five fields,
 - unixtime: Floating point number, time in seconds since 1st Jan, 1970.
 - linktype: Integer constant representing the root format of the
             packet as specified by the source.
 - origlen: Original length of the 'data' field.
 - data: Packet data as a bytearray.
 - identity: list of protocol identities.

Comparison operator methods and the length method are implemented.
Comparisons work on the value of 'unixtime', so a < b means a is older then b.
The length is 'origlen', so len(a) < len(b) means a was shorter then b."""

    __slots__ = ["unixtime", "linktype","origlen", "data", "identity"]

    def __init__(self, ut, lt, ol, dat):
        self.unixtime = ut
        self.linktype = lt
        self.origlen = ol
        self.data = bytearray(dat)
        self.identity = []

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
    print("{0} Linktype: {1}, Identity: {2},\
 Original length: {3}, Captured length: {4}".format(
        time.ctime(packet.unixtime),
        packet.linktype,
        "/".join(i.name for i in packet.identity),
        packet.origlen, len(packet.data)))


def parse_int(s):
    """Simple string -> integer parsing/guessing function.
Uses 'int' to do actual conversion, returns None on error."""
    try:
        if s.startswith("0x"):
            return int(s[2:], 16)
        if s.startswith("0o"):
            return int(s[2:], 8)
        if s.startswith("0b"):
            return int(s[2:], 2)

        return int(s)
    except ValueError:
        return None



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
    # Contracts a byte pair into a potentially compressed string.
    contract = lambda p: "{0:x}".format(p[0]*256 + p[1])
    
    if len(ip6b) != 16:
        return None

    return ":".join(contract(ip6b[i:i+2]) for i in range(0, 16, 2))

# Linktype definitions used by tcpdump and friends, http://www.tcpdump.org/linktypes.html 
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_AX25 = 3
LINKTYPE_IEEE802_5 = 6
LINKTYPE_ARCNET_BSD = 7
LINKTYPE_SLIP = 8
LINKTYPE_PPP = 9
LINKTYPE_FDDI = 10
LINKTYPE_PPP_HDLC = 50
LINKTYPE_PPP_ETHER = 51
LINKTYPE_ATM_RFC1483 = 100
LINKTYPE_RAW = 101
LINKTYPE_C_HDLC = 104
LINKTYPE_IEEE802_11 = 105
LINKTYPE_FRELAY = 107
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LTALK = 114
LINKTYPE_PFLOG = 117
LINKTYPE_IEEE802_11_PRISM = 119
LINKTYPE_IP_OVER_FC = 122
LINKTYPE_SUNATM = 123
LINKTYPE_IEEE802_11_RADIOTAP = 127
LINKTYPE_ARCNET_LINUX = 129
LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138
LINKTYPE_MTP2_WITH_PHDR = 139
LINKTYPE_MTP2 = 140
LINKTYPE_MTP3 = 141
LINKTYPE_SCCP = 142
LINKTYPE_DOCSIS = 143
LINKTYPE_LINUX_IRDA = 144
LINKTYPE_USER0 = 147
LINKTYPE_USER1 = 148
LINKTYPE_USER2 = 149
LINKTYPE_USER3 = 150
LINKTYPE_USER3 = 151
LINKTYPE_USER4 = 152
LINKTYPE_USER5 = 153
LINKTYPE_USER6 = 154
LINKTYPE_USER7 = 155
LINKTYPE_USER8 = 156
LINKTYPE_USER9 = 157
LINKTYPE_USER10 = 158
LINKTYPE_USER11 = 159
LINKTYPE_USER13 = 160
LINKTYPE_USER14 = 161
LINKTYPE_USER15 = 162
LINKTYPE_IEEE802_11_AVS = 163
LINKTYPE_BACNET_MS_TP = 165
LINKTYPE_PPP_PPPD = 166
LINKTYPE_GPRS_LLC = 169
LINKTYPE_LINUX_LAPD = 177
LINKTYPE_BLUETOOTH_HCI_H4 = 187
LINKTYPE_USB_LINUX = 189
LINKTYPE_PPI = 192
LINKTYPE_IEEE802_15_4 = 195
LINKTYPE_SITA = 196
LINKTYPE_ERF = 197
LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201
LINKTYPE_AX25_KISS = 202
LINKTYPE_LAPD = 203
LINKTYPE_PPP_WITH_DIR = 204
LINKTYPE_C_HDLC_WITH_DIR = 205
LINKTYPE_FRELAY_WITH_DIR = 206
LINKTYPE_IPMB_LINUX = 209
LINKTYPE_IEEE802_15_4_NONASK_PHY = 215
LINKTYPE_USB_LINUX_MMAPPED = 220
LINKTYPE_FC_2 = 224
LINKTYPE_FC_2_WITH_FRAME_DELIMS = 225
LINKTYPE_IPNET = 226
LINKTYPE_CAN_SOCKETCAN = 227
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_IEEE802_15_4_NOFCS = 230
LINKTYPE_DBUS = 231
LINKTYPE_DVB_CI = 235
LINKTYPE_MUX27010 = 236
LINKTYPE_STANAG_5066_D_PDU = 237
LINKTYPE_NFLOG = 239
LINKTYPE_NETANALYZER = 240
LINKTYPE_NETANALYZER_TRANSPARENT = 241
LINKTYPE_IPOIB = 242
LINKTYPE_MPEG_2_TS = 243
LINKTYPE_NG40 = 244
LINKTYPE_NFC_LLCP = 245
LINKTYPE_INFINIBAND = 247
LINKTYPE_SCTP = 248
LINKTYPE_USBPCAP = 249
LINKTYPE_RTAC_SERIAL = 250
LINKTYPE_BLUETOOTH_LE_LL = 251
LINKTYPE_NETLINK = 253
LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254
LINKTYPE_BLUETOOTH_BREDR_BB = 255
LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256
LINKTYPE_PROFIBUS_DL = 257
LINKTYPE_PKTAP = 258
LINKTYPE_EPON = 259
LINKTYPE_IPMI_HPM_2 = 260
LINKTYPE_ZWAVE_R1_R2 = 261
LINKTYPE_ZWAVE_R3 = 262
LINKTYPE_WATTSTOPPER_DLM = 263

# Definitions for the psuedopackets, for comparison purposes.
PACKET_MINAGE = Packet(float("-inf"), LINKTYPE_NULL, 0, b"")
PACKET_MAXAGE = Packet(float("+inf"), LINKTYPE_NULL, 0, b"")
