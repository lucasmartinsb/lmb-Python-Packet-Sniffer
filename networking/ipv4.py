class IPv4:
    def __init__(self, packet):
        self.version = packet.version
        self.header_length = packet.ihl * 4
        self.ttl = packet.ttl
        self.proto = packet.proto
        self.src = packet.src
        self.target = packet.dst
        self.data = bytes(packet.payload)