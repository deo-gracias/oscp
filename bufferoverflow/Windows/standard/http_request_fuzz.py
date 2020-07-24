#!/usr/bin/python
import requests
import sys, socket
from time import sleep

url = "http://127.0.0.1:8888/login"
password = "A"*100

while True:
	try: 
		               
		print "Trying to send %s bytes" % str(len(password))
		request = requests.session()

		login_info = {"username": "user","password": password}
		
		login_request = request.post(url, login_info)
		
		#print(login_request.text)
		answer = login_request.text

		sleep(1)
		
		password = password + "A"*100

	except:

		print "Fuzzing crashed at %s bytes" % str(len(password))
		sys.exit()


