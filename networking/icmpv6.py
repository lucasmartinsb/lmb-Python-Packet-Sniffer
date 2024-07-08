class ICMPv6:
    def __init__(self, packet):
        self.type = packet.type
        self.code = packet.code
        self.checksum = packet.cksum
        self.data = bytes(packet.payload)
