Packet Sniffer Tool

Overview
This Packet Sniffer tool captures and analyzes network packets in real-time using the Scapy library. It extracts and displays relevant information such as source and destination IP addresses, protocol types, and payload data. The tool is intended for educational purposes, focusing on ethical use to understand how network traffic works.


Features
Capture Network Packets: The tool captures all IPv4 packets in real-time.
Extract Information: It extracts and displays:
    Source IP address
    Destination IP address
    Protocol type
    Payload data (if present)
    Log Packets: All packet information is logged into a packet_log.txt file for further analysis.


Prerequisites
Python 3.x: Ensure Python is installed.
Scapy Library: Install Scapy using pip:
    pip install scapy


How to Use
    Run the Script: Execute the Python script to start sniffing packets.
        python packet_sniffer.py
    Monitor the Output: The script will print the captured packet information in the console.
    Stop Sniffing: Press the 'ESC' key to stop the packet sniffing process.
    Review Logs: Packet details are logged in packet_log.txt in the same directory as the script.


Code Explanation
Logging Setup: The script sets up logging to store packet details in a log file.
Packet Analysis Function:
    The packet_analysis(packet) function checks if the packet is an IPv4 packet.
    It extracts the source and destination IP addresses, protocol type, and payload data (if available).
    Packet information is printed to the console and logged in the packet_log.txt file.
Sniffing Functionality: The sniff() function from Scapy captures packets, applying the packet analysis function on each captured packet.
Stopping with ESC Key: The script includes a functionality to stop packet sniffing when the ESC key is pressed, utilizing the keyboard module to monitor key presses.


Ethical Considerations
This tool is intended solely for educational purposes. It should only be used on networks where you have explicit permission to capture traffic. Unauthorized sniffing of network traffic can be illegal and unethical. Always ensure compliance with legal and ethical guidelines when using this tool.
