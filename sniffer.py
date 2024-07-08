from scapy.all import *
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.ipv6 import IPv6
from networking.icmp import ICMP
from networking.icmpv6 import ICMPv6
from networking.tcp import TCP
from networking.udp import UDP
from networking.http import HTTP

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def process_packet(packet):
    eth = Ethernet(packet=packet)
    print('\nEthernet Frame:')
    print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))
    
    # IPv4 ou IPv6
    if 'IP' in packet:
        # IPv4
        ipv4 = IPv4(packet['IP'])
        print(TAB_1 + 'IPv4 Packet:')
        print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
        print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

    elif 'IPv6' in packet:
        # IPv6
        ipv6 = IPv6(packet['IPv6'])
        print(f"{TAB_1}IPv6 Packet:")
        print(f"{TAB_2}Version: {ipv6.version}, Traffic Class: {ipv6.traffic_class}, Flow Label: {ipv6.flow_label}")
        print(f"{TAB_2}Payload Length: {ipv6.payload_length}, Next Header: {ipv6.next_header}, Hop Limit: {ipv6.hop_limit}")
        print(f"{TAB_2}Source: {ipv6.src}")
        print(f"{TAB_2}Destination: {ipv6.dst}")

    if 'ICMP' in packet:
        icmp = ICMP(packet['ICMP'])
        print(TAB_1 + 'ICMP Packet:')
        print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
        print(TAB_2 + 'ICMP Data:')
        print(format_multi_line(DATA_TAB_3, icmp.data))
    
    elif 'ICMPv6ND_NS' in packet:
        icmpv6 = ICMPv6(packet['ICMPv6ND_NS'])
        print(TAB_1 + 'ICMP Packet:')
        print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmpv6.type, icmpv6.code, icmpv6.checksum))
        print(TAB_2 + 'ICMP Data:')
        print(format_multi_line(DATA_TAB_3, icmpv6.data))

    elif 'TCP' in packet:
        tcp = TCP(packet['TCP'])
        print(TAB_1 + 'TCP Segment:')
        print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
        print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
        print(TAB_2 + 'Flags:')
        print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
        print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))
        if len(tcp.data) > 0:
            # HTTP
            if tcp.src_port == 80 or tcp.dest_port == 80:
                print(TAB_2 + 'HTTP Data:')
                try:
                    http = HTTP(tcp.data)
                    http_info = str(http.data).split('\n')
                    for line in http_info:
                        print(DATA_TAB_3 + str(line))
                except:
                    print(format_multi_line(DATA_TAB_3, tcp.data))
            else:
                print(TAB_2 + 'TCP Data:')
                print(format_multi_line(DATA_TAB_3, tcp.data))
    elif 'UDP' in packet:
        udp = UDP(packet['UDP'])
        print(TAB_1 + 'UDP Segment:')
        print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))
    else:
        #Outro
        if ipv4:
            print(TAB_1 + 'Other IPv4 Data:')
            print(format_multi_line(DATA_TAB_2, ipv4.data))
        elif ipv6:
            print(TAB_1 + 'Other IPv6 Data:')
            print(format_multi_line(DATA_TAB_2, ipv6.data))


def main():
    filtro = input("Digite o filtro (em branco caso não deseja aplicar filtros): ")
    quant = input("Digite a quantidade de pacotes que deseja ler (em branco caso não queira limite): ")
    if quant:
        count = int(quant)
        sniff(prn=process_packet, filter=filtro, count=count)
    else:
        sniff(prn=process_packet, filter=filtro)

main()