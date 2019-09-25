#!/usr/bin/env python
import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_network", help="Please specify target or target network: example 192.168.1.0/24")

    (options, arguments) = parser.parse_args()
    print(options.target_network)
    if not options.target_network:
        parser.error("[-] Please specify  correct ip or network: example 192.168.1.1/24 or use --help for info.")
    return options
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    # arp_request_broadcast.show()
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # print(answered_list.summary())
    clients_list = []

    for element in answered_list:
        client_dict = {"ip":element[1].psrc, "mac": element[1].hwsrc}
        # print(element[1].psrc + "\t\t" + element[1].hwsrc)
        clients_list.append(client_dict)
        # print("------------------------------------------------")
    return clients_list

def print_result(result_list):
    print("IP\t\t\t MAC Address\n-------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


option = get_arguments()
scan_result = scan(option.target_network)
print_result(scan_result)

