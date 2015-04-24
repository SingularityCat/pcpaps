from . import core
from . import ip


class ICMPv6(core.ProtocolStub):
    """ICMPv6 stub."""
    name = "icmp6"


core.register_protocol(ICMPv6)
ip.register_ip_protocol(ICMPv6.name, ip.PROTO_IPV6_ICMP)
