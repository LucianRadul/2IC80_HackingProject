from scapy.all import *
import ipaddress

def rtrv_interfaces():
    return get_if_list()

def scan_hosts_scapy(interface: str):
    host_ip = get_if_addr(interface)
    subnet_mask = "255.255.255.0"
    host_ip = host_ip + "/" + subnet_mask
    net = ipaddress.ip_network(host_ip, strict = False)
    host = []
    ether = Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst = str(net))
    packet = ether/arp
    ans, unans = srp(packet, timeout = 2, iface = interface, verbose = False)

    for i in range(len(ans)):
        host.append((str(i) + ".", "IP: ", str(ans[i][1]["ARP"].psrc), 
        "and MAC: ", str(ans[i][1]["ARP"].hwsrc)))

    return host

def get_mac(ip):
    arp = Ether()/ARP(pdst = ip)
    resp = srp1(arp, verbose=0)
    return (resp[Ether].src)