#!/bin/sh

pydoc packet.capfile.core > ./doc/packet.capfile.core
pydoc packet.capfile.pcap > ./doc/packet.capfile.pcap

pydoc packet.identity.arp > ./doc/packet.identity.arp
pydoc packet.identity.core > ./doc/packet.identity.core
pydoc packet.identity.eth > ./doc/packet.identity.eth
pydoc packet.identity.icmp6 > ./doc/packet.identity.icmp6
pydoc packet.identity.icmp > ./doc/packet.identity.icmp
pydoc packet.identity.ip4 > ./doc/packet.identity.ip4
pydoc packet.identity.ip6 > ./doc/packet.identity.ip6
pydoc packet.identity.ip > ./doc/packet.identity.ip
pydoc packet.identity.tcp > ./doc/packet.identity.tcp
pydoc packet.identity.udp > ./doc/packet.identity.udp

pydoc packet.pipeline.merge > ./doc/packet.pipeline.merge
pydoc packet.pipeline.filter > ./doc/packet.pipeline.filter
pydoc packet.pipeline.identify > ./doc/packet.pipeline.identify

pydoc packet.common > ./doc/packet.common
pydoc packet.memorymap > ./doc/packet.memorymap


