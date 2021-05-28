#!/usr/bin/env python3
import os
import smtplib
from datetime import datetime
import requests


def email_sender():
    res = requests.get('https://ipinfo.io/')                            #api requesting information about geolocation
    dictionary = res.json()                                             #parse all the data into a single variable
    city = dictionary['city']                                           #extracting needed data from the json object
    prec_location= dictionary['loc'].split('.')                         #splitting an atribute to get 2 differen ones
    prec_lat = prec_location[0]
    prec_long = prec_location[1]
    host = dictionary["hostname"]                           
    timestamp = datetime.now()                                          #time stamp for the attack
    to = 'shodeb123@gmail.com'
    signaler = os.environ.get('EMAIL_SENDER')                           #enviromental variable access 
    password = os.environ.get('EMAIL_PASSWORD')
    subject = "MALICIOUS NETWORK HAS BEEN FOUND"
    body = "A malicious network has been detected"



    message = f"""From: NETWORK_SNIFFER {signaler}\n                    
    {subject} \n
    {body}\n
    {timestamp}\n
    Network: {host} in {city}
    LATITUDE: {prec_lat}
    LONGITUDE: {prec_long}
    """                                                                 #message being created

    alarm = smtplib.SMTP("smtp.gmail.com", 587)                         #settingup a smtp server
    alarm.starttls()                                                    #activating the tls protocol

    try:
        alarm.login(sender,password)                                    #login to the email
        print("Log In confirmed")
        alarm.sendmail(signaler,to,message)                             #sendint to the server
        print("Signal has been successfully sent")

    except:
        
        print("ERROR, please check your credentials")
        
if __name__ == '__main__':
    email_sender()

