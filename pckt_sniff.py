from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
import logging
from collections import Counter
import matplotlib.pyplot as plt

# Initialize logging
logging.basicConfig(filename='packet_sniffer.log', level=logging.INFO)

# Initialize statistics counters
packet_count = 0
ip_counter = Counter()

def packet_callback(packet):
    global packet_count
    global ip_counter

    # Extract Ethernet frame information
    src_mac = packet[Ether].src
    dst_mac = packet[Ether].dst

    # Initialize port variables with default values
    src_port = None
    dst_port = None

    # Check if IP layer is present
    if IP in packet:
        # Extract IP layer information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check if TCP layer is present
        if TCP in packet:
            # Extract TCP layer information
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print("\nTCP Packet:")
            print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")

            # Check if payload exists
            if hasattr(packet[TCP], 'payload') and hasattr(packet[TCP].payload, 'load'):
                # Extract the first 20 bytes of the payload (data)
                payload = packet[TCP].payload.load[:20]
                print(f"Payload (First 20 Bytes): {payload}")
            else:
                print("No payload in the packet.")
        else:
            # Handle UDP packets or other protocols
            print("\nPacket does not contain TCP layer.")
        
        # Logging: Write packet details to the log file
        logging.info(f"Packet {packet_count}: Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port}")

        # Statistics: Update counters
        packet_count += 1
        ip_counter.update([src_ip, dst_ip])

    else:
        print("\nPacket does not contain IP layer.")

# Specify the network interface to sniff on
network_interface = "Wi-Fi"

while True:
    print("\nSelect an option:")
    print("1. Capture TCP Packets")
    print("2. Capture UDP Packets")
    print("3. Exit")
    print("4. Show Statistics")
    print("5. Visualize IP Addresses")
    
    choice = input("Enter your choice (1-5): ")

    if choice == "1":
        filter_param = "tcp"
    elif choice == "2":
        filter_param = "udp"
    elif choice == "3":
        break
    elif choice == "4":
        # Display statistics
        print(f"Total Packets Captured: {packet_count}")
        print("Most frequent source IP addresses:")
        for ip, count in ip_counter.most_common():
            print(f"{ip}: {count} packets")
        continue
    elif choice == "5":
        # Visualize IP addresses
        labels, values = zip(*ip_counter.items())
        plt.bar(labels, values)
        plt.xlabel('IP Address')
        plt.ylabel('Packet Count')
        plt.title('Packet Sniffer - IP Address Visualization')
        plt.xticks(rotation=45)
        plt.show()
        continue
    else:
        print("Invalid choice. Please enter a number between 1 and 5.")
        continue

    # Sniff based on the user's choice and filter parameter
    sniff(iface=network_interface, prn=packet_callback, store=0, filter=filter_param, count=5)

# Final statistics display before exiting
print("\nFinal Statistics:")
print(f"Total Packets Captured: {packet_count}")
print("Most frequent source IP addresses:")
for ip, count in ip_counter.most_common():
    print(f"{ip}: {count} packets")
