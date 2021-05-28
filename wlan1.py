#!/usr/bin/env python3
import os	

#~~~~~~~~~~~~~~~ METHODS ~~~~~~~~~~~~~~~~~~~~~~~
def monitor_set() :

	os.system("sudo ip link set wlan1 down")                    #trhough bash comand line set the wlan1 interface off
	os.system("sudo iw wlan1 set monitor control")              #trhough bash comand line set the wlan1 interface to monitor mode
	os.system("sudo ip link set wlan1 up")                      #trhough bash comand line set the wlan1 interface on
	os.system("sudo iwconfig")                                  #displays the iw configuration from the system ( network interfaces )

#~~~~~~~~~~~~~~~~~~ MAIN ~~~~~~~~~~~~~~~~~~~~~~~

if __name__ == '__main__':
	monitor_set()
