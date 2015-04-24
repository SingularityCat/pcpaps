from .. import common

from . import ip
from . import core
from . import eth

from .core import uint16pack, uint16unpack

# IPv6 header format:
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version| Traffic Class |           Flow Label                  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Payload Length        |  Next Header  |   Hop Limit   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                         Source Address                        +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                      Destination Address                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class IPv6(core.CarrierProtocol):
    name = "ip6"

    __slots__ = {"payload_offset", "payload_length",
                 "_ver_tc_flow",
                 "_paylen", "_next", "_hoplim",
                 "_saddr",
                 "_daddr"}

    def __init__(self, data, prev):
        super().__init__(data, prev)
        self._calculate_checksums()

    def _calculate_checksums(self):
        self._ver_tc_flow = slice(0, 4)
        self._paylen = slice(4, 6)
        self._next = 6
        self._hoplim = 7
        self._saddr = slice(8, 20)
        self._daddr = slice(20, 36)

        self.payload_offset = 36
        self.payload_length = self.data[self._paylen]

    def get_protocol(self):
        """Returns the protocl number (next header) of this IPv6 header."""
        return self.data[self._next]

    def get_route(self):
        """Returns the route defined by this IPv6 header."""
        return bytes(self.data[self._saddr]) + bytes(self.data[self._daddr])

    def get_route_reciprocal(self):
        """Returns the reciprocal route of this IPv6 header."""
        return bytes(self.data[self._daddr]) + bytes(self.data[self._saddr])

    def get_payload_length(self):
        """Returns the payload length."""
        return self.payload_length

    def get_attributes(self):
        """Retrieve a set of attributes describing fields in this protocol."""
        return {
            "protocol": self.data[self._next],
            "saddr": bytes(self.data[self._saddr]),
            "daddr": bytes(self.data[self._daddr])
        }

    def set_attributes(self, attrs):
        """Alter packet data to match a set of protocol attributes."""
        pass

    def replace_hosts(self, hostmap):
        """Replace source/destination addresses."""
        ipmap = hostmap[core.AddrType.IP6.value]

        saddr = bytes(self.data[self._saddr])
        daddr = bytes(self.data[self._daddr])

        if saddr in ipmap:
            self.data[self._saddr] = ipmap[saddr]

        if daddr in ipmap:
            self.data[self._daddr] = ipmap[daddr]

        if self.next is not None:
            self.next.replace_hosts(hostmap)

    # IPv6 attrstr format.
    # <attr> = <key> "=" <value>
    # <attrstr> = <attr> | <attr> ";" <attrstr>
    #
    # Attributes are seperated by semicolons, which contain colon-seperated key-value pairs.
    # Valid keys are saddr, daddr, protocol
    @staticmethod
    def build_attributes(attrstr):
        """Creates a set of attributes from an attribute string."""
        attrdict = {}

        attrs = attrstr.split(";")
        for attr in attrs:
            try:
                # Split into kvp.
                k, v = attr.split("=")

                if k == "saddr" or k == "daddr":
                    attrdict[k] = common.ip6_str2bin(v)
                elif k == "protocol":
                    attrdict["protocol"] = common.parse_int(v)
            except ValueError:
                # Skip malformed attribute.
                pass

        return attrdict

    @staticmethod
    def interpret_packet(data, parent):
        """Interpret packet data for this protocol."""

        try:
            instance = IPv6(data, parent)
        except core.ProtocolFormatError:
            return None

        # Get protocol number for packet.
        protonum = instance.get_protocol()

        protocol = ip.lookup_ip_protocol(protonum)
        if protocol is not None:
            # Define payload view.
            payload_end = instance.payload_offset + instance.payload_length
            payload = instance.data[instance.payload_offset:payload_end]
            # Interpret payload.
            instance.next = protocol.interpret_packet(payload, instance)

        return instance

# Register protocol, as a ethertype handler and as a linktype handler.
core.register_protocol(IPv6)
core.register_linktype(IPv6.name, common.LinkType.IPV6.value)
eth.register_ethertype(IPv6.name, eth.ETHERTYPE_IP6)
