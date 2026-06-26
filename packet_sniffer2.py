from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):

    print("\n" + "=" * 50)
    print("PACKET CAPTURED")
    print("=" * 50)

    # IP Information
    if packet.haslayer(IP):
        print("Source IP      :", packet[IP].src)
        print("Destination IP :", packet[IP].dst)

    # Protocol Detection
    if packet.haslayer(TCP):
        print("Protocol       : TCP")
        print("Source Port    :", packet[TCP].sport)
        print("Destination Port:", packet[TCP].dport)

    elif packet.haslayer(UDP):
        print("Protocol       : UDP")
        print("Source Port    :", packet[UDP].sport)
        print("Destination Port:", packet[UDP].dport)

    elif packet.haslayer(ICMP):
        print("Protocol       : ICMP")

    # Payload Data
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors="ignore")
            print("Payload:")
            print(payload[:200])  # Display first 200 characters
        except:
            print("Payload could not be decoded.")

# Capture packets continuously
print("Starting Network Sniffer...")
print("Press CTRL + C to stop.\n")

sniff(prn=packet_callback, store=False)