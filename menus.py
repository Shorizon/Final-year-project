#!/usr/bin/env python3
from art import *
import finalscanner
import email_sender
import sms_sender
import wlan1
import os
import wifi
import time
import deauth
#~~~~~~~~~~~~~~~~~~~~~ VARIABLES ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
w = os.get_terminal_size().columns          #get the amount of columns in the terminal window
#~~~~~~~~~~~~~~~~~~~~~ METHODS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def cleanup():                              #clear the screen with a bash line
	os.system("clear")

def lines() :                               #get the amount of lines with a mod to make sure they aren't an odd number
	l = os.get_terminal_size().lines
	if ( (l % 2) == 1 ):
	 l = l - 1
	return int((l/2)-10)

def spacer(lines) :                         #gives us the autospacer to make the menu look neat
	for x in range(lines):
		print(" ")

def sub_main(l,w):                          #menu that gets printed each time the method gets called
	spacer(l)
	tprint("sho's secure wifi".center(w-70))
	print("[0].Conncect to a wifi AP".center(w))
	print("[1].Activate monitor".center(w))
	print("[2].Restart network".center(w))
	print("[3].Test sms_sender".center(w))
	print("[4].Test email_sender".center(w))
	print("[5].Start scanning".center(w))
	print("[6].Start broadband deauth attack".center(w))
	print("[7].exit".center(w))

def menu_main(l,w) :                        #write the logic of the menu
	while True:                             #makes it so we are inside the script as long as we give a valid input
		try:
			sub_main(l,w)
			print("	")
			print("	")
			print("	")
			selection=int(input("What would you like to do:\n ".center(w)))  #input needed to choose between the various options
			if selection==1:                                                 
				cleanup()                                                           
				wlan1.monitor_set()                                          #acceSs the monitor_set() method from wlan1 to set the interface into monitor mode
				l = l - 20
			elif selection==2:      
				cleanup()
				os.system("sudo service network-manager restart")#restarts the network manager services from linux 
				l = lines()
				spacer(l)
				tprint("net   restarting...".center(w-70))
				time.sleep(2)
				cleanup()
			elif selection==3:
				cleanup()
				sms_sender.SMS_sender()                                       #access SMS_sender() from sms_sender to send sms (this is a test to see if the credentials are right)
			elif selection==4:
				cleanup()
				email_sender.email_sender()                                   #access email_sender() from email_sender to send an email (this is a test to see if the credentials are right)
			elif selection==5:
				cleanup()
				os.system("sudo ./finalscanner.py")                           #launch the scanner to start sniffing (requires interface into monitor mode)
			elif selection==6:
				cleanup()
				l = lines()
				spacer(l)
				os.system("sudo ./deauth.py")                                 #launch the menu to send a deauth attack to disconnect possible victims from the malicious network
			elif selection==7:  
				cleanup()
				break                                                         #exits the script
			elif selection==0:
				cleanup()
				wifi.wifi_set()                                               #connect to a wifi AP
				l = l - 20
			else:
				break
		except ValueError:                                                    #in case the value is outside the range
			print("invalid choise".center(w))
	exit
	cleanup()
	l = lines()
	spacer(l)
	time.sleep(1)
	tprint("End of session".center(w-60))                                       
	print("Thank you for using the software".center(w))                       #when we exit the script
#~~~~~~~~~~~~~~~~~~~~~ MAIN  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if __name__ == '__main__':
	cleanup()
if __name__ == '__main__':
  menu_main(lines(),w)
