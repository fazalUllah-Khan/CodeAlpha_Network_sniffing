# Install Tools: use Python with libraries designed for networking:
# Scapy (powerful for packet sniffing & crafting)

# pip install scapy

#Capture Packets
from scapy.all import sniff
sniff(count=10)  # capture 10 packets

# Analyze Each Packet: Source & Destination IPs ,Protocols (TCP/UDP/ICMP/HTTP), Payload (if any, like part of a web request)


from scapy.all import sniff

def analyze_packet(packet):
    print(packet.summary())   # This will give quick overview
    packet.show()             # While it will show detailed breakdown

sniff(count=10, prn=analyze_packet)

# Extract Useful Info Instead of printing everything filtering

def analyze_packet(packet):
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        print(f"Source: {ip_layer.src} → Destination: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")  # number (6 = TCP, 17 = UDP, etc.)

# Add Protocol Names & Payload, dig into TCP/UDP payloads

def analyze_packet(packet):
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        print(f"IP {ip_layer.src} → {ip_layer.dst}")
        
        if packet.haslayer("TCP"):
            print("Protocol: TCP")
            print(f"Source Port: {packet['TCP'].sport}, Dest Port: {packet['TCP'].dport}")
        
        elif packet.haslayer("UDP"):
            print("Protocol: UDP")
            print(f"Source Port: {packet['UDP'].sport}, Dest Port: {packet['UDP'].dport}")
        
        # Show payload (if not empty)
        raw_data = bytes(packet["Raw"].load) if packet.haslayer("Raw") else None
        if raw_data:
            print(f"Payload: {raw_data[:50]}...")  # show first 50 bytes

# (Optional) Filter Traffic
sniff(filter="tcp port 80", prn=analyze_packet)

# Step 8: Test & Learn

# Run the program and browse a website → see packets appear.

# Try pinging another computer → notice ICMP packets.

# Watch how many small TCP/UDP packets carry even simple messages.
