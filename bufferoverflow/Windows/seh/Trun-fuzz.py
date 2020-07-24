#!/usr/bin/python

from boofuzz import *

host = '192.168.130.156'
port = 9999

def main():

	session = Session(target = Target(connection = SocketConnection(host, port, proto='tcp')), sleep_time = 3)

	s_initialize("VULN-TRUN")

	s_string("TRUN", fuzzable=False)
	s_delim(" ", fuzzable=False)
	s_string("BLAH")

	session.connect(s_get("VULN-TRUN"))
	session.fuzz()

if __name__ == "__main__":
	main()

