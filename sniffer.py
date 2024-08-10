"""Develop a packet sniffer tool that captures and analyzes network packets. 
Display relevant information such as source and destination IP addresses, protocols, and payload data. 
Ensure the ethical use of the tool for educational purposes."""

from scapy.all import sniff, IP, Raw
import logging
import keyboard
import threading

# Set up logging
logging.basicConfig(filename='packet_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Flag to control sniffing
sniffing = True

def packet_analysis(packet):
    global sniffing
    
    # Check if packet is IPv4
    if packet.haslayer(IP):
        # Get source and destination IP addresses
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        # Get protocol
        protocol = packet[IP].proto

        # Check if Raw layer exists
        if packet.haslayer(Raw):
            payload = packet[Raw].load
        else:
            payload = ""  # Set payload to an empty string if not present

        # Print packet information
        packet_info = (f"Source IP: {source_ip}\n"
                       f"Destination IP: {destination_ip}\n"
                       f"Protocol: {protocol}\n"
                       f"Payload: {payload}\n"
                       "--------------------------------")
        print(packet_info)

        # Log packet information
        logging.info(packet_info)

def stop_sniffing():
    global sniffing
    sniffing = False
    print("Sniffing stopped.")

# Function to start sniffing
def start_sniffing():
    sniff(filter="ip", prn=packet_analysis, stop_filter=lambda x: not sniffing)

# Monitor for ESC key press to stop sniffing
def monitor_keyboard():
    keyboard.wait('esc')
    stop_sniffing()

# Run sniffing and keyboard monitoring in separate threads
threading.Thread(target=start_sniffing).start()
monitor_keyboard()
