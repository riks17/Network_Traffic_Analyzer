from scapy.all import *

def packet_capture(interface, count):
    packets = sniff(iface=interface, count=count)
    return packets

def protocol_analysis(packets):
    protocol_count = {}
    for packet in packets:
        print("packet:",packet)
        # Check if the packet has the IP layer
        if IP in packet:
            protocol = packet[IP].proto
            if protocol in protocol_count:
                protocol_count[protocol] += 1
            else:
                protocol_count[protocol] = 1
    return protocol_count

# Example usage:
# Use the correct Wi-Fi interface name
# Replace 'your wifi/ethernet interface name here' with the actual Wi-Fi interface/Ethernet name on your system
wifi_interface = 'your wifi/ethernet interface name here'
captured_packets = packet_capture(wifi_interface, 10)  # Capture 10 packets for analysis

protocols = protocol_analysis(captured_packets)
print(protocols)
