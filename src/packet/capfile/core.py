"""
core:
 - Abstract classes for packet capture file readers/writers.
"""


class PacketReader:
    """Abstract class for packet readers.
Implementatons must provide the 'read_packet' method.
This class implements the __next__ method based on read_packet()"""


    def __iter__(self):
        """This makes the object an iterable.
A 'self iterable' as it simply returns self."""
        return self


    def __next__(self):
        """Iterator protocol interface."""
        pkt = self.read_packet()
        if pkt is None:
            raise StopIteration()

        return pkt


    def read_packet(self):
        """Abstract method read_packet.
Should return the 'Packet' object, or None if there are no packets left."""
        raise NotImplementedError("read_packet not implemented.")


    def close(self):
        """Abstract method close. Should close filesystem resources."""
        raise NotImplementedError("close not implemented.")


class PacketWriter:
    """Abstract class for packet writers.
Implementations must provide the 'write_packet' method."""


    def write_packet(self, packet):
        """Abstact method write_packet
Should take one argument, the 'Packet' object."""
        raise NotImplementedError("write_packet not implemented.")


    def close(self):
        """Abstract method close. Should cleanup any filesystem resources."""
        raise NotImplementedError("close not implemented.")
