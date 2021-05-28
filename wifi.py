#!/usr/bin/env python3

import os
import menus
#~~~~~~~~~~~~~~~ METHODS ~~~~~~~~~~~~~~~~~~~~~~~
def wifi_check() :
	os.system("nmcli d wifi list ifname wlan0")                                  #list the wifi that the interface wlan0 has access to
def connect_wifi():                                                             
	while True:
		network_name = input('please enter the network name: ')                  #input the wifi that the interface wlan0 has access to
		if network_name in ['quit','exit','quit()','exit()','main menu','back']: #check if the user wants to exit
			menus.cleanup()
			menus.spacer(menus.lines())
			break
		network_pass = input('please enter the network password: ')              #input the password to the wifi that the interface wlan0 has access to
		if network_pass in ['quit','exit','quit()','exit()','main menu','back']: #check if the user wants to exit
			menus.cleanup()
			menus.spacer(menus.lines())
			break
		try:
			os.system(f'sudo nmcli d wifi connect "{network_name}" password {network_pass} ifname wlan0') #connects using the ssid and the pass 
		except:
			print("An error has been detected, please insert credentials again") #if it fails asks for credential 
	exit

def wifi_set():                                                                  #puts both the methods to run at once                         
	wifi_check()
	connect_wifi()


#~~~~~~~~~~~~~~~~~~ MAIN ~~~~~~~~~~~~~~~~~~~~~~~
if __name__  == '__main__' :
	wifi_set()
	

