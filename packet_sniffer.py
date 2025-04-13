from scapy.all import sniff

# Define a function to process the captured packets
def packet_handler(packet):
    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst}")

# Start sniffing the network
print("Starting packet sniffing...")
sniff(prn=packet_handler, store=0)
