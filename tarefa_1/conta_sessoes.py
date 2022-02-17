# Aluno: Tiago Serique Valadares
# Curso: Ciencia da Computaçao
# GRR: 20195138


from scapy.all import *
from scapy.layers.inet import *


def add_sessions(cls, packet, sessions_dict):
	ip_src = packet[IP].src
	ip_dst = packet[IP].dst

	sport = packet[cls].sport
	dport = packet[cls].dport

	tuple_1 = (ip_src, sport, ip_dst, dport)
	tuple_2 = (ip_dst, dport, ip_src, sport)

	if tuple_1 in sessions_dict:
		if ( payload != None ):
			sessions_dict[f"{tuple_1}"].append(payload)
	
	elif tuple_2 in sessions_dict:
		if ( payload != None ):
			sessions_dict[f"{tuple_2}"].append(payload)
	
	else:
		payload = hexdump(packet[cls].payload, dump=True)
		sessions_dict[f"{tuple_1}"] = []

		if ( payload != None ):
			sessions_dict[f"{tuple_1}"].append(payload)




packets = sniff(timeout=60)
wrpcap("trace.pcap", packets)

tcp_pkt_count = 0
udp_pkt_count = 0
ip_pkt_list  = []
tcp_sessions_dict = {}
udp_sessions_dict = {}

for packet in packets:
	if ( IP in packet ):
		ip_pkt_list.append(packet)
		
		if ( TCP in packet ):
			tcp_pkt_count += 1
		
		elif ( UDP in packet ):
			udp_pkt_count += 1

for packet in ip_pkt_list:
	if ( TCP in packet ):
		add_sessions(TCP, packet, tcp_sessions_dict)

	if ( UDP in packet ):
		add_sessions(UDP, packet, udp_sessions_dict)

total_pkts 	= len(packets)
ip_total 	= len(ip_pkt_list)
tcp_total 	= tcp_pkt_count
udp_total 	= udp_pkt_count
sessions_tcp_total = len(tcp_sessions_dict)
sessions_udp_total = len(udp_sessions_dict)
not_ip_total = total_pkts - ip_total

print(f"{total_pkts} pacotes no total\n")
print(f"{ip_total} pacotes IP\n")
print(f"{tcp_total} pacotes TCP\n")
print(f"{udp_total} pacotes UDP\n")
print(f"{sessions_tcp_total} sessões TCP\n")
print(f"{sessions_udp_total} sessões UDP\n")
print(f"{not_ip_total} pacotes não-IP")
