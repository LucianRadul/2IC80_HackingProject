import tkinter as tk
from scapy.all import *
import tkinter.ttk as ttk
from scapy_functions import *
import threading
from multiprocessing import Process

''' Global variables '''

interface = ""
curr_lbx_selected = ""
target_1 = ""
target_2 = ""
redirect_ip = ""
process_arp_poisoner = Process()
process_dns_poisoner = Process()


''' Functions '''

def scan_hosts():
    hosts = scan_hosts_scapy(interface)

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
    print(curr_lbx_selected)

def add_target_1():
    global target_1
    target_1 = curr_lbx_selected[2]
    lbl_target_1.config(text = target_1)
    message = target_1 + " successfully added as target 1!"
    tk.messagebox.showinfo(title = "Target selection", message = message)

def add_target_2():
    global target_2
    target_2 = curr_lbx_selected[2]
    lbl_target_2.config(text = target_2)
    message = target_2 + " successfully added as target 2!"
    tk.messagebox.showinfo(title = "Target selection", message = message)

def arp_spoofing():
    global process_arp_poisoner
    process_arp_poisoner = Process(target=poison_arp_cache, args=(target_1, target_2))
    process_arp_poisoner.start()
    message = "ARP spoofing successful!"
    tk.messagebox.showinfo(title = "ARP spoofing", message = message)

def arp_stop():
    process_arp_poisoner.terminate()
    restore_arp_table(target_1, target_2)
    restore_arp_table(target_2, target_1)
    message = "ARP spoofing stopped!"
    tk.messagebox.showinfo(title = "ARP spoofing", message = message)

def dns_spoofing():
    global process_dns_poisoner
    process_dns_poisoner = Process(target=dns_sniffer, args=(target_1, target_2, redirect_ip))
    process_dns_poisoner.start()
    message = "DNS spoofing successful!"
    tk.messagebox.showinfo(title = "DNS spoofing", message = message)

def dns_stop():
    process_dns_poisoner.terminate()
    message = "DNS spoofing stopped!"
    tk.messagebox.showinfo(title = "DNS spoofing", message = message)

def set_redirect_ip(event):
    global redirect_ip
    redirect_ip = ent_dns_redirect.get()
    message = redirect_ip + " successfully added as the redirect server!"
    tk.messagebox.showinfo(title = "False server", message = message)
    

def clicked():
    text = txtf_interface.get()
    test.configure(text = "  Interface selected: " + txtf_interface.get())


''' Define window '''
window = tk.Tk()
window.title("Allegedly the best light-weight hacking tool")
window.geometry("700x500+400+150")


''' Create tabs '''
tabControl = ttk.Notebook(window)
tab_interface = tk.Frame(tabControl)
tab_hosts = tk.Frame(tabControl)
tab_targets = tk.Frame(tabControl)
tab_attacks = tk.Frame(tabControl)

tabControl.add(tab_interface, text = "Interface")
tabControl.add(tab_hosts, text = "Hosts")
tabControl.add(tab_targets, text = "Targets")
tabControl.add(tab_attacks, text = "Attacks")
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


''' Attacks tab '''

fr_attack_btns = tk.Frame(tab_attacks)

btn_arp_spoof = ttk.Button(fr_attack_btns, text = "Start ARP spoofing", command = arp_spoofing)
btn_arp_spoof.grid(column = 0, row = 0)

btn_arp_stop = ttk.Button(fr_attack_btns, text = "Stop ARP spoofing", command = arp_stop)
btn_arp_stop.grid(column = 1, row = 0)

btn_dns_spoof = ttk.Button(fr_attack_btns, text = "Start DNS spoofing", command = dns_spoofing)
btn_dns_spoof.grid(column = 0, row = 1)

btn_dns_stop = ttk.Button(fr_attack_btns, text = "Stop DNS spoofing", command = dns_stop)
btn_dns_stop.grid(column = 1, row = 1)

ent_dns_redirect = ttk.Entry(fr_attack_btns)
ent_dns_redirect.bind("<Return>", set_redirect_ip)
ent_dns_redirect.grid(column = 2, row = 1)

fr_attack_btns.place(relx = 0.5, rely = 0.05, anchor = "c")




window.mainloop()