import os

from . import pcap

#extension = os.path.splitext(fpath)[1]

class PacketFileUnknwonFormatError(RuntimeException):
    """Exception raised when a file is unable to be opened."""
    pass

def packetfile_open_read(fpath):
    """Function that tries to open a packet capture file."""
    extension = os.path.splitext(fpath)[1]

    # Open the file.
    pfile = open(fpath, "rb")

    if extension == "pcap":
        # Try PcapReader if file extension is 'pcap':
        try:
            return PcapReader(pfile)
        except PcapFormatError err:
            pfile.seek(0, 0)

    # Dumb method
    try:
        return PcapReader(pfile)
    except PcapFormatError err:
        pfile.seek(0, 0)

    
