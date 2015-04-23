from .. import common

from . import core
from . import ip

from .core import uint16pack, uint16unpack

# RFC 768: User Datagram Protocol

#  0      7 8     15 16    23 24    31 
# +--------+--------+--------+--------+
# |     Source      |   Destination   |
# |      Port       |      Port       |
# +--------+--------+--------+--------+
# |                 |                 |
# |     Length      |    Checksum     |
# +--------+--------+--------+--------+
# |                                    
# |          data octets ...           
# +---------------- ...                
#       User Datagram Header Format    


# Minimum size of a valid UDP header.
UDP_MIN_SIZE = 8


class UDP(core.CarrierProtocol):
    name = "udp"

    __slots__ = {"_sport", "_dport", "_len", "_chksum", "payload_offset"}

    def __init__(self, data, prev):
        super().__init__(data, prev)

        if len(data) < UDP_MIN_SIZE:
            raise core.ProtocolFormatError("Truncated UDP frame.")
        self._calculate_offsets()

    def _calculate_offsets(self):
        # Fixed offsets.
        self._sport = slice(0, 2)
        self._dport = slice(2, 4)
        self._len = slice(4, 6)
        self._chksum = slice(6, 8)

        length = uint16unpack(self.data[self._len])
        self.payload_offset = 8

    def get_attributes(self):
        """Retrieve a set of attributes describing fields in this protocol."""
        return {
            "sport": bytes(self.data[self._dport]),
            "dport": bytes(self.data[self._sport])
        }

    def set_attributes(self, attrs):
        """Alter packet data to match a set of protocol attributes."""
        pass

    def recalculate_checksums(self):
        """Recalculate the checksum for this UDP header."""
        if self.next is not None:
            self.next.recalculate_checksums()

    # <attr> = <key> "=" <value>
    # <attrstr> = <attr> | <attr> ";" <attrstr>
    #
    # Attributes are seperated by semicolons, which contain colon-seperated key-value pairs.
    # Valid keys are sport, dport
    @staticmethod
    def build_attributes(attrstr):
        """Creates a set of attributes from an attribute string."""
        attrdict = {}

        attrs = attrstr.split(";")
        for attr in attrs:
            try:
                # Split into kvp.
                k, v = attr.split("=")

                if k == "sport" or k == "dport":
                    attrdict[k] = common.interpret_int(v)

            except ValueError:
                # Skip malformed attribute.
                pass

        return attrdict

    @staticmethod
    def interpret_packet(data, parent):
        """Interpret packet data for this protocol."""
        try:
            instance = UDP(data, parent)
        except core.ProtocolFormatError:
            return None

        return instance


core.register_protocol(UDP)
ip.register_ip_protocol(UDP.name, ip.PROTO_UDP)
