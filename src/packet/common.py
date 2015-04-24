"""
common:
 - Definition for the 'Packet' class
 - Functions for operating on the 'Packet' class.
 - Functions for handling generic user input, i.e. parse_int.
 - Functions for converting a ip4/ip6/mac address to string form and back.
Contains two constants, PACKET_MINAGE and PACKET_MAXAGE, two
psuedopackets being older then or newer then all other packets, respectively.
"""

import enum

import time
import binascii


class Packet:
    """Class consisting of five fields,
     - unixtime: Floating point number, time in seconds since 1st Jan, 1970.
     - linktype: Integer constant representing the root format of the
                 packet as specified by the source.
     - origlen: Original length of the 'data' field.
     - data: Packet data as a bytearray.
     - identity: The root protocol instance.

    Comparison operator methods and the length method are implemented.
    Comparisons work on the value of unixtime, so a < b means a is older then b.
    The length is 'origlen', so len(a) < len(b) means a was shorter then b."""

    __slots__ = ["unixtime", "linktype", "origlen", "data", "identity"]

    def __init__(self, ut, lt, ol, dat):
        self.unixtime = ut
        self.linktype = lt
        self.origlen = ol
        self.data = bytearray(dat)
        self.identity = None

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

    def __str__(self):
        """Creates a human readable string summary of this packet."""
        try:
            lnkt = LinkType(self.linktype).value
        except ValueError:
            lnkt = "(unknown)"

        if self.identity is not None:
            ident = "/".join(i.name for i in self.identity)
            if not self.identity.is_complete():
                ident += " (incomplete)"
        else:
            ident = "(not identified)"

        fmtargs = (
            time.ctime(self.unixtime), lnkt, ident,
            self.origlen, len(self.data)
        )

        return "{0} Linktype: {1}, Identity: {2},\
 Original length: {3}, Captured length: {4}".format(*fmtargs)



def parse_int(intstr):
    """Simple string -> integer parsing/guessing function.
Uses 'int' to do actual conversion, returns None on error."""
    try:
        if intstr.startswith("0x"):
            return int(intstr[2:], 16)
        if intstr.startswith("0o"):
            return int(intstr[2:], 8)
        if intstr.startswith("0b"):
            return int(intstr[2:], 2)

        return int(intstr)
    except ValueError:
        return None


def parse_hexbytes(hexstr):
    """Simple hex string -> bytes parsing function.
Uses binascii to do actual conversion, returns None on error."""
    try:
        return binascii.unhexlify(hexstr)
    except binascii.Error:
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
    expand = (lambda l: int(l, 16) // 256, lambda h: int(h, 16) % 256)

    try:
        # Check if the string contains the zero-compressed section.
        # This can only appear once, RFC 5952 section 2.2.
        if "::" in ip6s:
            ip6i_start, ip6i_end = ip6s.split("::")

            ip6i_start = [f(pair) for pair in ip6i_start.split(":") for f in expand]
            ip6i_end = [f(pair) for pair in ip6i_end.split(":") for f in expand]
            ip6i = ip6i_start + [0]*(16 - (len(ip6i_start) + len(ip6i_end))) + ip6i_end
        else:
            #ip6i = [expand(pair) for pair in ip6s.split(":")]
            ip6i = [f(pair) for pair in ip6s.split(":") for f in expand]

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
class LinkType(enum.Enum):
    """Linktype Enumerations matching those used in tcpdump and pcap files."""
    NULL = 0
    ETHERNET = 1
    AX25 = 3
    IEEE802_5 = 6
    ARCNET_BSD = 7
    SLIP = 8
    PPP = 9
    FDDI = 10
    PPP_HDLC = 50
    PPP_ETHER = 51
    ATM_RFC1483 = 100
    RAW = 101
    C_HDLC = 104
    IEEE802_11 = 105
    FRELAY = 107
    LOOP = 108
    LINUX_SLL = 113
    LTALK = 114
    PFLOG = 117
    IEEE802_11_PRISM = 119
    IP_OVER_FC = 122
    SUNATM = 123
    IEEE802_11_RADIOTAP = 127
    ARCNET_LINUX = 129
    APPLE_IP_OVER_IEEE1394 = 138
    MTP2_WITH_PHDR = 139
    MTP2 = 140
    MTP3 = 141
    SCCP = 142
    DOCSIS = 143
    LINUX_IRDA = 144
    USER0 = 147
    USER1 = 148
    USER2 = 149
    USER3 = 150
    USER4 = 151
    USER5 = 152
    USER6 = 153
    USER7 = 154
    USER8 = 155
    USER9 = 156
    USER10 = 157
    USER11 = 158
    USER12 = 159
    USER13 = 160
    USER14 = 161
    USER15 = 162
    IEEE802_11_AVS = 163
    BACNET_MS_TP = 165
    PPP_PPPD = 166
    GPRS_LLC = 169
    LINUX_LAPD = 177
    BLUETOOTH_HCI_H4 = 187
    USB_LINUX = 189
    PPI = 192
    IEEE802_15_4 = 195
    SITA = 196
    ERF = 197
    BLUETOOTH_HCI_H4_WITH_PHDR = 201
    AX25_KISS = 202
    LAPD = 203
    PPP_WITH_DIR = 204
    C_HDLC_WITH_DIR = 205
    FRELAY_WITH_DIR = 206
    IPMB_LINUX = 209
    IEEE802_15_4_NONASK_PHY = 215
    USB_LINUX_MMAPPED = 220
    FC_2 = 224
    FC_2_WITH_FRAME_DELIMS = 225
    IPNET = 226
    CAN_SOCKETCAN = 227
    IPV4 = 228
    IPV6 = 229
    IEEE802_15_4_NOFCS = 230
    DBUS = 231
    DVB_CI = 235
    MUX27010 = 236
    STANAG_5066_D_PDU = 237
    NFLOG = 239
    NETANALYZER = 240
    NETANALYZER_TRANSPARENT = 241
    IPOIB = 242
    MPEG_2_TS = 243
    NG40 = 244
    NFC_LLCP = 245
    INFINIBAND = 247
    SCTP = 248
    USBPCAP = 249
    RTAC_SERIAL = 250
    BLUETOOTH_LE_LL = 251
    NETLINK = 253
    BLUETOOTH_LINUX_MONITOR = 254
    BLUETOOTH_BREDR_BB = 255
    BLUETOOTH_LE_LL_WITH_PHDR = 256
    PROFIBUS_DL = 257
    PKTAP = 258
    EPON = 259
    IPMI_HPM_2 = 260
    ZWAVE_R1_R2 = 261
    ZWAVE_R3 = 262
    WATTSTOPPER_DLM = 263

# Definitions for the psuedopackets, for comparison purposes.
PACKET_MINAGE = Packet(float("-inf"), LinkType.NULL.value, 0, b"")
PACKET_MAXAGE = Packet(float("+inf"), LinkType.NULL.value, 0, b"")
