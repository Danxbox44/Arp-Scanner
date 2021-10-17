from scapy.all import * 
import argparse

parser = argparse.ArgumentParser(description="Enter Target IP Address, Interface, and IP Range")
parser.add_argument('Interface', help = "Interface for the scan")
parser.add_argument('Iprange', help = "Ip Range for the scan")
args = parser.parse_args()

interface = args.Interface
iprange = args.Iprange
broadcastMac = "ff:ff:ff:ff:ff:ff"

packet = Ether(dst=broadcastMac)/ARP(pdst = iprange)

ans, unans = srp(packet, timeout = 2, iface = interface, inter=0.1)

for send,receive in ans:
    print(receive.sprintf(r"%Ether.src% - %ARP.psrc%"))