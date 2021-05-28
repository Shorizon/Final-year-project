#!/usr/bin/python3
import requests
import os


def SMS_sender():

    number = os.environ.get('PHONE')                # enviromental variable
    
    resp = requests.post('https://textbelt.com/text', {     #api being requested 
  'phone': f'{number}',                                     #phone number
  'message': 'MALICIOUS NETWORK HAS BEEN FOUND',            #message
  'key': 'textbelt',                                        #api key needed to send SMS
    })
    print(resp.json())                                      #response given by the request

if __name__ == '__main__':
    SMS_sender()
