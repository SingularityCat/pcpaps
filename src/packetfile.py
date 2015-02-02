import collections

PacketInfo = collections.namedtuple("PacketInfo",
    ["network", "timestamp", "nanosec", "caplen", "origlen"])

class PacketReader:
    def read_packet(data=True):
        raise NotImplemented("read_packet unimplemented.")    
    
class PacketWriter:
    def write_packet(packet_info, packet_data):
        raise NotImplemented("write_packet unimplemented.")    
