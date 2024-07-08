class Ethernet:
    def __init__(self, packet):
        self.dest_mac = packet.dst
        self.src_mac = packet.src
        self.proto = packet.type
        self.data = bytes(packet.payload)