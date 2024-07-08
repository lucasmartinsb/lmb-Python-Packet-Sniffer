class UDP:
    def __init__(self, packet):
        self.src_port = packet.sport
        self.dest_port = packet.dport
        self.size = packet.len
        self.data = bytes(packet.payload)