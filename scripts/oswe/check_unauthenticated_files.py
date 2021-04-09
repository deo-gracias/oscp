import requests
import sys

requests.packages.urllib3.disable_warnings()

if len(sys.argv) < 3:
	print("%s <target> <list>" % sys.argv[0])
	sys.exit(1)

target = sys.argv[1]
urlfile = sys.argv[2]

class bcolors:
	Green= '\033[92m'
	Yellow= '\033[93m'
	ENDC = '\033[0m'


def print_success(string):
	print bcolors.Green + string + bcolors.ENDC


def print_action(string):
	print bcolors.Yellow +string+ bcolors.ENDC


def url_is_unauthed( url):
	r = requests.get(url , verify=False, allow_redirects=False)
	if r.status_code == 200:
		return True

	r = requests.post(url , verify=False, allow_redirects=False)
	if r.status_code == 200:
		return True

	return False


def url_is_a_redirect(url):
	r = requests.get(url , verify=False, allow_redirects=False)
	if r.status_code == 302:
		return True
	return False


f = open(urlfile)
urls = f.readlines()
f. close()


print_action("(!) Checking for unauthed access ... ")


for path in urls:
	url = "https://%s/spywall%s"% (target, path.rstrip())
	if url_is_unauthed( url):
		print_success("(+ ) %s : UNAUTHED!"% url)