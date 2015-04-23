from .. import common
from .. import memorymap

from . import ip
from . import core
from . import eth

from .core import uint16pack, uint16unpack



# RFC 791: INTERNET PROTOCOL
#
# Internet Header Format
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|  IHL  |Type of Service|          Total Length         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Identification        |Flags|      Fragment Offset    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Time to Live |    Protocol   |         Header Checksum       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Source Address                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Destination Address                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Options                    |    Padding    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# IHL is the header size in terms of 4 bytes.
# Total Length is the size of the whole packet in bytes.
# Fragment Offset is measured in terms of 8 bytes.

# IPv4 flags
IP4_FLAG_MORE_FRAGMENTS = 0b001
IP4_FLAG_DONT_FRAGMENT = 0b010
IP4_FLAG_EVIL_BIT = 0b100  # RFC 3514 :)


def ip4_extract_fragment_info(fragdat):
    frag_flags = (fragdat[0] & 0xE0) >> 5
    frag_offset = (fragdat[0] & 0x1F) * 16 + fragdat[1]
    return frag_flags, frag_offset

# Support for fragmented IP packets.
fragment_trackers = {}


class FragmentTracker:
    """Used to track fragmented IP packets."""
    __slots__ = {"frags", "deferred_frags", "next_offset"}

    def __init__(self):
        self.frags = []
        self.deferred_frags = []
        self.next_offset = 0

    def add_fragment(self, frag):
        """Returns True if packet is complete, False if otherwise."""
        ir = self.try_insert(frag)
        if ir is None:
            # Tracking complete!
            return True
        elif ir is True:

            # Tracking incomplete, but we've advanced.
            # We can try and redo any deferred packets here.
            try_again = True
            while try_again:
                try_again = False
                # copy deferred list.
                current_deferred = self.deferred_frags[:]
                # clear main list.
                self.deferred_frags.clear()

                # Iterate over deferred list.
                for frag in current_deferred:
                    tr = self.try_insert(frag)

                    if tr is None:
                        # Tracking complete!
                        return True

                    elif tr is True:
                        try_again = True

        return False

    def try_insert(self, frag):
        """
        Try to add a fragment to the frags list.
        Tristate return:
         - None  = last fragment added.
         - True  = fragment added, more needed.
         - False = fragment deferred.
        """
        frag_flags, frag_offset, _ = frag.get_fraginfo()
        if frag_offset == self.next_offset:
            self.frags.append(frag)
            self.next_offset += frag.payload_length
            if (frag_flags & IP4_FLAG_MORE_FRAGMENTS) == 0:
                # Fragment tracking finished!
                return None
            # Successfully inserted.
            return True
        else:
            self.deferred_frags.append(frag)
            # Added to deferred pool.
            return False

class IPv4(core.CarrierProtocol):
    name = "ip4"

    __slots__ = {"payload_offset", "payload_length"
                 "_ver_ihl", "_tos", "_len",
                 "_id", "_flags_fragoff",
                 "_ttl", "_proto", "_chksum",
                 "_saddr",
                 "_daddr",
                 "logical_payload_length"}

    def __init__(self, data, prev):
        """"""
        super().__init__(data, prev)

        if len(data) < (5*4):
            raise core.ProtocolFormatError("Data too short for valid header.")
        elif ((data[0] & 0xF0) >> 4) != 4:
            raise core.ProtocolFormatError("Data is not a IPv4 header.")

        self._calculate_offsets()

    def _calculate_offsets(self):
        """"""
        # Fixed offsets
        self._ver_ihl = 0
        self._tos = 1
        self._len = slice(2, 4)
        self._id = slice(4, 6)
        self._flags_fragoff = slice(6, 8)
        self._ttl = 8
        self._proto = 9
        self._chksum = slice(10, 12)
        self._saddr = slice(12, 16)
        self._daddr = slice(16, 20)

        # Get header length.
        ihl = self.data[self._ver_ihl] & 0x0F

        self.payload_offset = (ihl * 4)  # IHL is in terms of 4 bytes.
        self.payload_end = uint16unpack(self.data[self._len])
        self.payload_length = self.payload_end - self.payload_offset
        self.logical_payload_length = self.payload_length

    def get_protocol(self):
        """Returns the protocl number of this IP header."""
        return self.data[self._proto]

    # Used by the interpreter/fragment tracker.
    def get_fraginfo(self):
        """Returns the flags, fragment offset and fragment ident."""
        fragdat = self.data[self._flags_fragoff]
        frag_flags, frag_offset = ip4_extract_fragment_info(fragdat)
        frag_id = self.get_route() + bytes(self.data[self._id]) + bytes(self.get_protocol(),)
        return frag_flags, frag_offset*8, frag_id

    def get_route(self):
        """Returns the route defined by this IP header."""
        return bytes(self.data[self._saddr]) + bytes(self.data[self._daddr])

    def get_route_reciprocal(self):
        """Returns the reciprocal route of this IP header."""
        return bytes(self.data[self._daddr]) + bytes(self.data[self._saddr])

    def get_payload_length(self):
        """Returns the (possibly logical) payload length."""
        return self.logical_payload_length

    def get_attributes(self):
        """Retrieve a set of attributes describing fields in this protocol."""
        return {
            "protocol": self.data[self._proto],
            "saddr": bytes(self.data[self._saddr]),
            "daddr": bytes(self.data[self._daddr])
        }

    def set_attributes(self, attrs):
        """Alter packet data to match a set of protocol attributes."""
        pass

    def replace_hosts(self, hostmap):
        """Replace source/destination addresses."""
        ipmap = hostmap[core.AddrType.IP4.value]

        saddr = bytes(self.data[self._saddr])
        daddr = bytes(self.data[self._daddr])

        if saddr in ipmap:
            self.data[self._saddr] = ipmap[saddr]

        if daddr in ipmap:
            self.data[self._daddr] = ipmap[daddr]

        if self.next is not None:
            self.next.replace_hosts(hostmap)

    def recalculate_checksums(self):
        """Recalculate the checksum for this IP header."""
        if self.next is not None:
            self.next.recalculate_checksums()

        # Nullify the checksum and replace.
        self.data[self._chksum] = b"\x00\x00"
        self.data[self._chksum] = ip.checksum(self.data[:self.payload_offset])

    @staticmethod
    def reset_state():
        """Resets the fragment_trackers dict."""
        fragment_trackers.clear()

    # IPv4 attrstr format.
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

                if k == "saddr" or k == "daddr":
                    attrdict[k] = common.ip4_str2bin(v)
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
            instance = IPv4(data, parent)
        except core.ProtocolFormatError:
            return None

        # Get protocol number for packet.
        protonum = instance.get_protocol()

        # Get the fragment flags / fragment offset.
        frag_flags, frag_offset, frag_id = instance.get_fraginfo()

        if frag_offset > 0 or \
            (frag_flags & IP4_FLAG_MORE_FRAGMENTS) != 0:
            # Packet is fragmented!
            instance.completed = False

            if frag_id not in fragment_trackers:
                fragment_trackers[frag_id] = FragmentTracker()

            # Get the fragment tracker.
            ft = fragment_trackers[frag_id]

            # Add this fragment to the tracker.
            ft_complete = ft.add_fragment(instance)

            if ft_complete:
                # Fragmented packet is complete!
                del fragment_trackers[frag_id]
                views = []

                logical_length = 0
                for frag in ft.frags:
                    logical_length += frag.payload_length
                    frag.completed = True
                    # Add payload memoryview to views list.
                    views.append(
                        frag.data[frag.payload_offset:frag.payload_end]
                    )
                # Determine protocol (based off protocol number of last packet)
                protocol = ip.lookup_ip_protocol(protonum)
                if protocol is not None:
                    # Define payload view.
                    mapped_data = memorymap.memorymap(views)
                    # Interpret payload.
                    next = protocol.interpret_packet(mapped_data, instance)

                # Assign child and logical length to next of all fragments.
                for frag in ft.frags:
                    frag.next = next
                    frag.logical_payload_length = logical_length

        else:
            # No fragmentation!
            # Determine protocol.
            protocol = ip.lookup_ip_protocol(protonum)
            if protocol is not None:
                # Define payload view.
                payload = instance.data[instance.payload_offset:instance.payload_end]
                # Interpret payload.
                instance.next = protocol.interpret_packet(payload, instance)
        return instance


# Register protocol, as a ethertype handler and as a linktype handler.
core.register_protocol(IPv4)
core.register_linktype(IPv4.name, common.LinkType.IPV4.value)
eth.register_ethertype(IPv4.name, eth.ETHERTYPE_IP4)
