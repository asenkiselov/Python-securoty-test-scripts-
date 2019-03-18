#!/usr/bin/env python

import subprocess
import optparse
import re

#using function get arguments  to extract user input

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC")
    parser.add_option("-m", "--mac", dest="new_mac", help="new MAC address ")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        #code to handle error
        parser.error("[-] Please specify an interface, use --help for info.")

    elif not options.new_mac:
        parser.error("[-] Please specify a new mac, use --help for info.")
    return options


# using subprocess to change mac address
def change_mac(interface, new_mac):
    print("[+] Changing MAC address for " + interface + " to " + new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])
    # print(subprocess.call(["ifconfig", interface]))

def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    # using regular expresions to find onle tha mac address

    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)

    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("[-] Could not read MAC address")

options = get_arguments()

current_mac = get_current_mac(options.interface)
print("Current MAC = " + str(current_mac))

change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if  current_mac == options.new_mac:
    print("[+] MAC address was successfully changed to " + current_mac)
else:
    print("[-] MAC address did not get changed.")



