
from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        protocol_name = packet.sprintf("%IP.proto%")
        print(f"    Protocol: {protocol_name} ({ip_layer.proto})")
        
        if packet.haslayer(TCP):
            print(f"    TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"    UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")

        if packet.haslayer(Raw):
            payload = packet.getlayer(Raw).load
            print(f"    Payload: {payload[:100]}...") # Show first 100 bytes
        print("\n" + "="*50 + "\n")

print("[*] Starting network sniffer. Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
