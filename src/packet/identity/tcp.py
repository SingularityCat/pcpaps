from .. import common

from . import core
from . import ip

from .core import uint16pack, uint16unpack, uint32pack, uint32unpack

# RFC 793: Transmission Control Protocol.

#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source Port          |       Destination Port        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Sequence Number                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Acknowledgment Number                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Data |           |U|A|P|R|S|F|                               |
# | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
# |       |           |G|K|H|T|N|N|                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Checksum            |         Urgent Pointer        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Options                    |    Padding    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             data                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

tcp_routes = {}

class TCPStateMachine:
    __slots__ = {"initiator_route", "responder_route"}
    def __init__(self, ir, rr):
        self.initiator_route = ir
        self.responder_route = rr


class TCP(core.CarrierProtocol):
    name = "tcp"

    __slots__ = {"payload_offset", "port",
                 "_sport", "_dport",
                 "_seqnum",
                 "_acknum",
                 "_offset_byte", "_flags_byte", "_window"
                 "_chksum", "_urgptr"}

    def __init__(self, data, prev):
        super().__init__(data, prev)
        self._calculate_offsets()
        self.port = None

    def _calculate_offsets(self):
        self._sport = slice(0, 2)
        self._dport = slice(2, 4)
        self._seqnum = slice(4, 8)
        self._acknum = slice(8, 12)
        self._offset_byte = 12
        self._flags_byte = 13
        self._window = slice(14, 16)
        self._chksum = slice(16, 18)
        self._urgptr = slice(18, 20)

        # Data offset is in multiples of 4.
        self.payload_offset = ((self.data[self._offset_byte] & 0xF0) >> 2)


    def get_attributes(self):
        """Retrieve a set of attributes describing fields in this protocol."""
        return {
            "port": self.port,
            "sport": uint16unpack(self.data[self._dport]),
            "dport": uint16unpack(self.data[self._sport])
        }

    def set_attributes(self, attrs):
        """Alter packet data to match a set of protocol attributes."""
        pass

    def recalculate_checksums(self):
        """Recalculate the checksum for this TCP header."""
        if self.next is not None:
            self.next.recalculate_checksums()

        if isinstance(self.prev, core.CarrierProtocol):
            # Nullify the checksum and replace.
            self.data[self._chksum] = b"\x00\x00"

            if self.prev.name == "ip4":
                # TCP over IPv4 psuedoheader
                phdr = self.prev.get_route() +\
                    uint16pack(self.prev.get_payload_length()) +\
                    bytes((0, ip.PROTO_TCP))
            elif self.prev.name == "ip6":
                # TCP over IPv6 psuedoheader
                phdr = self.prev.get_route() +\
                    uint32pack(self.prev.get_payload_length()) +\
                    bytes((0, 0, 0, ip.PROTO_TCP))
            else:
                # Unknown carrier. Huh. Use -no- psuedoheader.
                phdr = b""

            # Actual TCP header/payload
            if len(self.data) % 2 == 0:
                ahdr = bytes(self.data)
            else:
                ahdr = bytes(self.data) + b"\x00"
            self.data[self._chksum] = ip.checksum(phdr + ahdr)

    @staticmethod
    def reset_state():
        """Resets the tcp_routes dict."""
        tcp_routes.clear()

    # <attr> = <key> "=" <value>
    # <attrstr> = <attr> | <attr> ";" <attrstr>
    #
    # Attributes are seperated by semicolons, which contain colon-seperated key-value pairs.
    # Valid keys are 
    @staticmethod
    def build_attributes(attrstr):
        """Creates a set of attributes from an attribute string."""
        attrdict = {}

        attrs = attrstr.split(";")
        for attr in attrs:
            try:
                # Split into kvp.
                k, v = attr.split("=")

            except ValueError:
                # Skip malformed attribute.
                pass

        return attrdict

    @staticmethod
    def interpret_packet(data, parent):
        """Interpret packet data for this protocol."""
        instance = TCP(data, parent)

        if parent is None or not isinstance(parent, core.CarrierProtocol):
            # Cannot possibly track without a source/destination!
            return instance

        # Both route and rev_route should resolve to the same
        # TCP state machine object.
        route = parent.get_route()

        if route not in tcp_routes:
            rev_route = parent.get_route_reciprocal()
            tsm = TCPStateMachine(route, rev_route)

            tcp_routes[route] = tsm
            tcp_routes[rev_route] = tsm


        return instance

core.register_protocol(TCP)
ip.register_ip_protocol(TCP.name, ip.PROTO_TCP)
