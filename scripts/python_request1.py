import requests
from colorama import Fore, Back, Style 
requests.packages.urllib3.\
disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}


def format_text(title,item):

	cr = '\r\n'

	section_break = cr + "*" * 20 + cr

	item = str(item)

	text = Style.BRIGHT + Fore.RED + title + Fore.RESET + section_break + item + section_break 
	return text

r = requests.get('http://192.168.5.1:80/',verify=False)
#r = requests.get('http://192.168.5.1:80/',verify=False, proxies=proxies)

print(format_text('r.status_code is: ',r.status_code))
print(format_text('r.headers is: ',r.headers))


print(format_text('r.cookies is: ',r.cookies))
print(format_text('r.text is: ',r.text))