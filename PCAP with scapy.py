from scapy.all import rdpcap
import pandas as pd

#Change the file path accordingly
file_path = "C:/TH OWL/SEM 1/NWS 2024/Scapy Lab PCAP/def_con_23_sample.pcap"
packets = rdpcap(file_path)
print ("Summary of packets in the pcap file:")
packets.summary()

print ("Details of the individual packets in the pcap file:")
for packet in packets:
    print (packet)

data ={
"Ethernet": [],
    "IP": [],
    "TCP": [],
    "UDP": [],
} 
     
#Representation of the data in a data frame
df = pd.DataFrame(data) 
print(df)
#Access different layers of the first packet
ether_layer = packet[0]  # Ethernet layer
ip_layer = packet[1]  # IP layer
tcp_layer = packet[2]  # TCP layer

# Print the layers
print("Ethernet layer:", ether_layer)
print("IP layer:", ip_layer)
print("TCP layer:", tcp_layer)



