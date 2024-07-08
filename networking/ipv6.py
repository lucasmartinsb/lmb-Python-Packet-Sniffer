class IPv6:
    def __init__(self, packet):
        self.version = packet.version
        self.traffic_class = packet.tc
        self.flow_label = packet.fl
        self.payload_length = packet.plen
        self.next_header = packet.nh
        self.hop_limit = packet.hlim
        self.src = packet.src
        self.dst = packet.dst
        self.data = bytes(packet.payload)