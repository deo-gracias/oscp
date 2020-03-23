#!/usr/bin/python

__author__ = "Devharsh Trivedi"
__edited_author__ = "Luc SEMASSA"
__copyright__ = "Copyright 2018, Devharsh Trivedi"
__license__ = "GPL"
__version__ = "1.4"
__maintainer__ = "Devharsh Trivedi"
__email__ = "devharsh@live.in"
__email_edited_author__ = "lucsemassa@gmail.com"
__status__ = "Production"

import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

try:

	for link in sys.argv[1:]:
		page = requests.get(link)
		soup = BeautifulSoup(page.text, "lxml")
		extlist = set()
		intlist = set()
		js_int_list = set()
		js_ext_list = set()
		
		for a in soup.findAll("a", attrs={"href":True}):
			if len(a['href'].strip()) > 1 and a['href'][0] != '#' and 'javascript:' not in a['href'].strip() and 'mailto:' not in a['href'].strip() and 'tel:' not in a['href'].strip():
				if 'http' in a['href'].strip() or 'https' in a['href'].strip():
					if urlparse(link).netloc.lower() in urlparse(a['href'].strip()).netloc.lower():
						intlist.add(a['href'])
					else:
						extlist.add(a['href'])
				else:
					intlist.add(a['href'])

		for a in soup.findAll("form", attrs={"action":True}):
			if len(a['action'].strip()) > 1 and a['action'][0] != '#' and 'javascript:' not in a['action'].strip() and 'mailto:' not in a['action'].strip() and 'tel:' not in a['action'].strip():
				if 'http' in a['action'].strip() or 'https' in a['action'].strip():
					if urlparse(link).netloc.lower() in urlparse(a['action'].strip()).netloc.lower():
						intlist.add(a['action'])
					else:
						extlist.add(a['action'])
				else:
					intlist.add(a['action'])

		for a in soup.findAll("script", attrs={"src":True}):
			if len(a['src'].strip()) > 1 and a['src'][0] != '#' and 'mailto:' not in a['src'].strip():
				if 'http' in a['src'].strip() or 'https' in a['src'].strip():
					if urlparse(link).netloc.lower() in urlparse(a['src'].strip()).netloc.lower():
						js_int_list.add(a['src'])
					else:
						js_ext_list.add(a['src'])
				else:
					js_int_list.add(a['src'])
		
		print('\n')
		print(link)
		print('---------------------')
		print('\n')
		print(str(len(intlist)) + ' internal links found:')
		print('\n')
		for il in intlist:
			print(il)
		print('\n')
		print(str(len(extlist)) + ' external links found:')
		print('\n')
		for el in extlist:
			print(el)
		print('\n')
		print(str(len(js_int_list)) + ' internal javascript links found:')
		print('\n')
		for il in js_int_list:
			print(il)
		print('\n')
		print(str(len(js_ext_list)) + ' external javascript links found:')
		print('\n')
		for el in js_ext_list:
			print(el)
		print('\n')
		
except Exception as e:
	print(e)
