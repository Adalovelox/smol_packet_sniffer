from scapy.all import *
from scapy.layers.http import HTTPRequest

def sniff_sniff(iface=None):
    if iface:
        sniff(filter="port 80" , iface=iface, prn=processed_packet, store=False)
    else:
        sniff(filter="port 80" , prn=processed_packet, store=False)
def processed_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        if packet.haslayer(IP):
            ip1 = packet[IP].src
            ip2 = packet[IP].dst
            method = packet[HTTPRequest].Method.decode()
            print(f"{ip1} Requested {url} with {method} for {ip2}")
        else:
            method = packet[HTTPRequest].Method.decode()
            print(f"Requested {url} with {method}")
        if packet.haslayer(Raw):
            keys = ["email","username", "password", "pass"]
            load = packet.haslayer(Raw).load
            for key in keys:
                if key in load:
                    print("Possibly vulnerable data: " + load)
                    break
        print(packet)

if __name__ == "__main__":


    sniff_sniff()