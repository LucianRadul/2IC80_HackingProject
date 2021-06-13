
# 2IC80_HackingProject

This is a project made for the 2IC80 Offensive Computer Security Course (Q4, 2021) at Eindhoven University of Technology.

The purpose of this project was to deliver an analysis and reproduction of a number of non-trivial attack scenarios. For this, we chose to reproduce and illustrate the following three attacks: ARP Spoofing, DNS Spoofing, TCP Telnet Session Hijack with Reverse Shell.

## Setup

For the setup of the attacks we used 3 virtual machines:

 1. Windows XP - Provided for use in the course 2IC80.
 2. Kali Linux (Attacker) - Used the Kali Linux Distribution to illustrate an attacker machine.
 3. Kali Linux (Server) - Used another Kali Linux Machine to illustrate a local area network server.

To ensure the VM's had access to the internet, and were configured as machines on the personal LAN, that is they received IP addresses and acted as any other machine on our personal LAN, we configured the network adapters in the VM settings as follows, for each of the three VM's:

 1. Adapter 1 - Bridged Adapter
 2. Adapter 2 - NAT

At the end of the configuration, the VM's obtain IP addresses corresponding to the LAN on which they are on, through DHCP.

For the Windows XP VM, the latest compatible version of Firefox has been installed.

The following packages are installed on both the Kali VM's.

 1. netcat
 2. scapy (already present on Kali Linux)
 3. telnetd
 4. xinetd
 5. apache server
 6. nmap

All packages have been installed using: 
> sudo apt-get install #package-name#

Special configuration has been done for the telnetd, xinetd packages. After installation using:

> sudo apt-get install telnetd
> sudo apt-get install xinetd
> sudo service xinetd start

The following command creates the inetd.conf file. Nothing needs to be modified inside it.
> sudo vim /etc/inetd.conf

The following file, needs to be modified

> sudo vim /etc/xinetd.conf

And this needs to be added at the end of the file:

>  defaults   
>  
>  {  
>  
> #Please note that you need a log_type line to be able to use log_on_success  
> #and log_on_failure. The default is the following :  
> #log_type = SYSLOG daemon info  
> 
>  instances = 60  
>  
>   log_type = SYSLOG authpriv 
>   
>   log_on_success = HOST PID 
>   
>   log_on_failure = HOST   
>       
> cps =25 30  
> 
>   }

Afterwards, the service needs to be restarted using

> sudo /etc/init.d/xinetd restart

To confirm that the service works use

> nmap -p 23 127.0.0.1

Note that the xinetd service must be started everytime the VM is restarted. Moreover, the apache server service must be started on the Server VM using:

> sudo service apache2 start



