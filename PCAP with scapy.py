from scapy.all import *

#Change the file path accordingly
file_path = "C:/TH OWL/SEM 1/NWS 2024/def_con_23_sample.pcap"

#Reading the pcap file
# packets = rdpcap(file_path)
packets = sniff(offline=file_path)

#Printing the summary of the packets
print ("Summary of packets in the pcap file:")
packets.nsummary()

#Trying by accessing the first packet
first_packet = packets[0]
print ("First packet in the pcap file:")
print (first_packet)

#Inspecting the layers of the first packet
print ("Layers of the first packet in the pcap file:")
#Ethernet Layer
eth_layer = first_packet[Ether]
print ("Ethernet Layer:")
print (eth_layer)

#IP Layer
ip_layer = first_packet[IP]
print ("IP Layer:")
print (ip_layer)

#TCP Layer
tcp_layer = first_packet[TCP]
print ("TCP Layer:")
print (tcp_layer)

#Filtering and Analyzing the packets
tcp_packets = [pkt for pkt in packets if TCP in pkt]
udp_packets = [pkt for pkt in packets if UDP in pkt]

#Specific IP addresses or ports 
#Filter packets with a specific source IP address
print("Filtering packets with a specific source IP address:")
filtered_packets_ip = [pkt for pkt in packets if pkt.haslayer(IP) and pkt[IP].src == '192.168.0.125']

#Filter packets with a specific destination port (e.g., port 502 for TCP)
print("Filtering packets with a specific port:")
filtered_packets_port = [pkt for pkt in packets if pkt.haslayer(TCP) and pkt[TCP].dport == 502]

#Specific Protocols (Eg: HTTP, DNS)
#Filter HTTP packets (assuming port 80 or 440 for HTTP)
print("Filtering HTTP packets:")
filtered_packets_http = [pkt for pkt in packets if pkt.haslayer(TCP) and pkt[TCP].dport == 440]

#Filter DNS packets (port 53)
print("Filtering DNS packets:")
filtered_packets_dns = [pkt for pkt in packets if pkt.haslayer(UDP) and pkt[UDP].dport == 53]

#Extract relevant information from filtered packets
filtered_packets = tcp_packets + udp_packets + filtered_packets_ip + filtered_packets_port + filtered_packets_http + filtered_packets_dns

for pkt in filtered_packets:
    if IP in pkt:
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Unknown"
        print(f"Protocol: {proto}, Source IP: {pkt[IP].src}, Destination IP: {pkt[IP].dst}, "
              f"Source Port: {pkt[TCP].sport if TCP in pkt else pkt[UDP].sport}, "
              f"Destination Port: {pkt[TCP].dport if TCP in pkt else pkt[UDP].dport}")

#Mention possibilities for statistics (packet size, counts, etc.)
#Packet size statistics
packet_sizes = [len(pkt) for pkt in filtered_packets]
print("Packet Size Statistics:")
print(f"Minimum Packet Size: {min(packet_sizes)} bytes")
print(f"Maximum Packet Size: {max(packet_sizes)} bytes")
print(f"Average Packet Size: {sum(packet_sizes) / len(packet_sizes)} bytes")



