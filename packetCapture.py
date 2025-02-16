from scapy.all import *

def packet_capture(interface, count):
    packets = sniff(iface=interface, count=count)
    return packets

# Example usage:
# Use the correct interface name for Windows, such as 'Ethernet', 'Wi-Fi', etc.
# Replace 'your wifi/ethernet interface name here' with the actual interface name from your Windows system
interface_name = 'your wifi/ethernet interface name here'
captured_packets = packet_capture(interface_name, 10)

# Print a summary of each captured packet
for packet in captured_packets:
    print(packet.summary())
