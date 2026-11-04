"""Packet captures and network data."""

type("network", parents = ["bytes"], abstract = True, description = "Packet captures and network data")

type("network.pcap", parents = ["network"], mime = "application/vnd.tcpdump.pcap", ext = ["pcap", "cap", "dmp"], description = "libpcap capture")
type("network.pcapng", parents = ["network"], mime = "application/x-pcapng", ext = ["pcapng"], description = "pcapng capture")
type("network.tcp-packet", parents = ["network"], mime = "application/tcp", ext = ["tcp"], description = "TCP segment")
type("network.udp-packet", parents = ["network"], mime = "application/udp", ext = ["udp"], description = "UDP datagram")
