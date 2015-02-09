import os

from . import pcap

#extension = os.path.splitext(fpath)[1]

class PacketFileUnknwonFormatError(RuntimeError):
    """Exception raised when a file is unable to be opened."""
    pass

def packetfile_open_read(fpath, **kwargs):
    """Function that tries to open a packet capture file for reading."""
    extension = os.path.splitext(fpath)[1]

    # Open the file.
    pfile = open(fpath, "rb")

    if extension == "pcap":
        # Try PcapReader if file extension is 'pcap':
        try:
            return pcap.PcapReader(pfile, **kwargs)
        except pcap.PcapFormatError:
            pfile.seek(0, 0)

    # Dumb method
    try:
        return pcap.PcapReader(pfile, **kwargs)
    except pcap.PcapFormatError:
        pfile.seek(0, 0)

    raise PacketFileUnknownFormatError("Can't identify file format.")


def packetfile_open_write(fpath, **kwargs):
    """Function that tries to open a packet capture file for writing."""
    extension = os.path.splitext(fpath)[1]

    # Open the file.
    pfile = open(fpath, "wb")

    if extension == "pcap":
        # Use PcapWriter
        return pcap.PcapWriter(pfile, **kwargs)
