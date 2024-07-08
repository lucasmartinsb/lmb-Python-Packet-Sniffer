class ICMP:
    def __init__(self, packet):
        self.type = packet.type
        self.code = packet.code
        self.checksum = packet.chksum
        self.data = bytes(packet.payload)
