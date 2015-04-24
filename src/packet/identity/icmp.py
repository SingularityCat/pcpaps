from . import core
from . import ip


class ICMP(core.ProtocolStub):
    """ICMP stub."""
    name = "icmp"


core.register_protocol(ICMP)
ip.register_ip_protocol(ICMP.name, ip.PROTO_ICMP)
