from scapy.all import *
from multiprocessing import Process

tcp_sniff_proc = Process()
ip_client = "10.10.10.102"
filter_tcp = "tcp and host " + ip_client
tcp_pkt_lst = []
last_tcp_pkt = TCP()

def last_tcp(pkt):
	global tcp_pkt_lst
	if (pkt[IP].src == ip_client and pkt.haslayer(TCP) and pkt[TCP].flags == "A" and pkt[TCP].dport == 23):
		tcp_pkt_lst.append(pkt)
		print(pkt.summary())
	

def test_sniff(pkt):
	global tcp_pkt_lst, last_tcp_pkt
	ip_client = "10.10.10.102"

	if (pkt[IP].src == ip_client and pkt.haslayer(TCP) and pkt[TCP].flags == "S" and pkt[TCP].dport == 23):
		sniff(filter = "tcp and host 10.10.10.102", timeout = 10, prn = last_tcp) #timeout should be 60
		print("Sniff complete")
		last_tcp_pkt = tcp_pkt_lst[-1][TCP]
		print(last_tcp_pkt.show())
		

def tcp_sniff():
	ip_src = " and host 10.10.10.102"
	filt_telnet = "tcp" + ip_src
	sniff(filter = filt_telnet, prn = test_sniff)

def main():
	target = "10.10.10.102"
	tcp_sniff_proc = Process(target = tcp_sniff)
	tcp_sniff_proc.start()

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print('Interrupted')
		try:
			tcp_sniff_proc.terminate()
			sys.exit(0)
		except SystemExit:
			os._exit(0)
