class TCP:
    def __init__(self, packet):
        self.src_port = packet.sport
        self.dest_port = packet.dport
        self.sequence = packet.seq 
        self.acknowledgment = packet.ack
        self.offset_reserved_flags = packet.dataofs * 4
        self.flag_urg = (packet.flags & 0x20) >> 5
        self.flag_ack = (packet.flags & 0x10) >> 4
        self.flag_psh = (packet.flags & 0x08) >> 3
        self.flag_rst = (packet.flags & 0x04) >> 2
        self.flag_syn = (packet.flags & 0x02) >> 1
        self.flag_fin = packet.flags & 0x01
        self.data = bytes(packet.payload)  # Captura os dados do payload