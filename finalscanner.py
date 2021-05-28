#!/usr/bin/env python3
import logging
from datetime import datetime
from scapy.all import *
import sys
import os
import time
import sqlite3
import multiprocessing
import sms_sender
import email_sender

#~~~~~~~~~~~~~~~~~~~~~~~~~ VARIABLES ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
seen = 0
beacon = Dot11Beacon
response = Dot11ProbeResp
db_connection = sqlite3.connect('spoofing_cases.db')                      #create a connection with sqlite3 to make and manage databases
db_cursor = db_connection.cursor()                                        #cursor to use DB
log_form = '%(asctime)s.%(msecs)03d %(name)s %(levelname)s %(message)s'   #log format
frequency_timer = 5.0                                                     #delay time for sweeping
monitor_interface = 'wlan1'                                               #sets up the main interface to use to scan
to_be_checked = {'SKYVUMBJ(5.0)': ['80:72:15:79:3D:AD'], 'testssid': ['ID:ID:ID:ID:ID:ID'], } #the ssid_MAC to be checked(need to be whitelisted)
logging.basicConfig( level=logging.DEBUG, format=log_form, datefmt='%Y-%m-%d %H:%M:%S', ) #needed for the logging (formating the output) 
#~~~~~~~~~~~~~~~~~~~~~~~~~ METHODS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#~~~~~~~~~~~~~~~~~~~~~ DATABASE METHODS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def db_setup():                                                           #Creates a new table if a table doesnt exits and name the fields
	db_cursor.execute("""CREATE TABLE IF NOT EXISTS `spoofing_cases` ( `malicious_bssid` TEXT PRIMARY KEY UNIQUE NOT NULL, `seen_the_first_time` DATETIME NOT NULL, `seen_the_last_time` DATETIME NOT NULL, `count` INTEGER NOT NULL );""")
	db_connection.commit()                                                #commit the changes
	
def db_new_malicious_bssid(malicious_bssid):                              #log new cases of malicius attempts 
  seen_the_first_time = datetime.now()
  seen_the_last_time = seen_the_first_time
  count = 1
  db_cursor.execute("""INSERT INTO spoofing_cases (malicious_bssid, seen_the_first_time, seen_the_last_time, count) VALUES(?, ?, ?, ?);""", (malicious_bssid, seen_the_first_time, seen_the_last_time, count))
  db_connection.commit()

def close_connections(status):                                            #close the connection with the db as we don't want to keep it open when we log off
  logging.debug(f"children processes to end: {len(multiprocessing.active_children())}") 
  for child in multiprocessing.active_children():                         #check every child process(thanks to multiprocessing)
    logging.debug(f"ending child process with pid {child.pid}")            
    child.terminate()                                                     #close the process  
  logging.debug("securely closing the database connection")
  db_cursor.close()                                                       #close connection to the db cursor
  db_connection.close()                                                   #close connection to the db
  logging.info("closed all connection")
  sys.exit(status)                                                        
  
def db_update_malicious_bssid(malicious_bssid, count):                    #update the count and the "seen_the_last_time" parameter whenever multiple instances of the spoofing have been detected
  seen_the_last_time = datetime.now()
  count += 1
  db_cursor.execute("""UPDATE spoofing_cases SET seen_the_last_time=(?), count=(?) WHERE malicious_bssid=(?)""",
                  (seen_the_last_time, count, malicious_bssid,)
                )
  db_connection.commit()

def db_log_malicious_bssid(malicious_bssid):                              #logs cases depending on if the mac_adress was seen before
  db_cursor.execute("""SELECT * from spoofing_cases WHERE malicious_bssid=(?)""",
                  (malicious_bssid,)
                )
  malicious_bssid_record = db_cursor.fetchone()
  if malicious_bssid_record:
    db_update_malicious_bssid(malicious_bssid, malicious_bssid_record[-1])
  else:
    db_new_malicious_bssid(malicious_bssid)
#~~~~~~~~~~~~~~~~~~~~ CHANNELS AND SCANNING METHODS  ~~~~~~~~~~~~~~~
def switch_channel():                                                     #go through channels using the bash commandline
  while True:
    for x in range(1,14):
      print(f"channel being checked is: {x}")
      os.system(f"iwconfig {monitor_interface} channel {x}")
      time.sleep(frequency_timer)

def packet_checkers(packet):                                              #go trough the packets and their content
  unchecked_layers = [beacon, response]                                   #gives the arguments to check the DOT11 specification and a DOT11 probe response
  unckecked_packets = False
  for layer in unchecked_layers:                                          #checks all the layers that haven't been visited by the script yet
    if packet.haslayer(layer):                                            #checks if the packet has different layers
      unckecked_packets = True                                            #marks them to be checked
  if not unckecked_packets:                                               #no layers have been found
    return
  network_name = packet[Dot11Elt].info.decode()                           #set up a variable with a 802.11 Information Element as argument giving us the name of the network
  client = packet[Dot11].addr1                                            #set up a variable with the address of the broadcast  
  mac_adress = packet[Dot11].addr2                                        #set up a variable with the mac adress of the spoofer
  if network_name in to_be_checked.keys():                                #checks all the current networks against the given whitelisted network_name and mac adresses
    print("  ")
    logging.info(f" match with network_name: {network_name}")
    logging.info(f"with a mac_adress: {mac_adress}")
    if mac_adress not in to_be_checked[network_name]:                     #if the mac adresses do not match with the whitelisted ones
      if packet.haslayer(beacon):                                         #checks for layers
        malicious_bssid = f"malicious network found for: '{network_name}' - malicious mac adress: {mac_adress}" 
        db_log_malicious_bssid(malicious_bssid)                           #log the case in the db
        logging.warning(malicious_bssid)                                  #outputs the malicious mac_adress
        global seen
        if seen == 0 or seen % 14 == 0:
           seen = seen + 1
           sms_sender.SMS_sender()
           email_sender.email_sender()
      elif packet.haslayer(response):
        malicious_bssid = f"client '{client}' received a  malicious response to probe from BSSID: {mac_adress}"
        logging.warning(malicious_bssid)                                  #logs the warning with the mac adress 
        db_log_malicious_bssid(malicious_bssid)                           #logs the warning into the db
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ MAIN CODE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if __name__ == '__main__':
  logging.info("starting")
  
  try:                                                                    #start the database and check for error handling                                               
    db_setup()
  except Exception as e:
    logging.critical(f"error: {e}")
    sys.exit(1)

  try:                                                                    #creates different process for different channels
    channel_switcher_tool = multiprocessing.Process(target=switch_channel)
    channel_switcher_tool.daemon = True                                   #runs in parallel with the main program without exiting 
    channel_switcher_tool.start()                                         #start multi processing
    logging.debug(f"channel_switcher_tool on channel: {channel_switcher_tool.pid}")
    channel_checker_tool = multiprocessing.Process(target=sniff, kwargs={ 'iface': monitor_interface, 'prn': packet_checkers }) #creates a sniffer for the channels as they go through
    channel_checker_tool.daemon = True                                    #runs in parallel with the main program without exiting 
    channel_checker_tool.start()                                          #start multi processing 
    logging.debug(f"channel_checker_tool on channel: {channel_checker_tool.pid}") 
    channel_checker_tool.join()                                           
  except KeyboardInterrupt as e:
    logging.info("caught KeyboardInterrupt")                              #only way to end the script atm / cltr+C 
    close_connections(0)
  except Exception as e:
    logging.critical(f"caught unhandled exception: {e}")
    close_connections(1)                                                 

  close_connections(0)                                                    #close connection in case anything happens
