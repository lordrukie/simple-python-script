#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    # Set the ip address to ask
    arp_request = scapy.ARP(pdst=ip)
    # Set the broadcast mac for send
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine address and broadcast mac so can be send over srp.
    arp_request_broadcast = broadcast/arp_request
    # Get the answer list from ip address that we set to ask before.
    # Add some timeout so the program will continue if not answered in 1 second.
    answerd_list = scapy.srp(arp_request_broadcast, verbose=False, timeout=1)[0]

    clients_list = []
    for element in answerd_list:
        client_dic = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dic)
    return clients_list

def print_result(result_list):
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------")

    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])

scan_result = scan("192.168.89.1/24")
print_result(scan_result)