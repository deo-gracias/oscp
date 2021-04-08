#'\n' => new line
#'\t' => tab
#'r' => voids special character
#
#   r'\n' => means \ and n (apply only for string, not pattern)
#
#


##function
#match => check if the pattern is the start of the string
# bool(re.match(pattern, string ))
# bool(re.match('a', 'abc' )) returns true while bool(re.match('b', 'abc' )) returns false

#print the match or search
#
#re.match('c', "caabfc").group()
#re.match('c', "caabfc").group(0)

#re.search('c\w+', "ccaabfc").group()
#
#
#
#search => search anywhere
#findall
#re.findall('n|a',"bcdefnc abcda" ) #find all pulls out all instances
#re.findall('\w+',"bcdefnc abcda" ) returns ['bcdefnc', 'abcda']
#When using group with findall, only the group is showed

#
#match.group(0) => all maching group
#
#match.group(1) => first maching group
#match.group(2) => second maching group
#match.group(n) => nth maching group
#
#
#match.groups() => all group in an array
#
#finditer
#it = re.finditer('([A-Za-z]+) \w+ (\d+) (\w+)', string)
#
#next(it).groups()
#
#for element in it:
#    print (element.group(1,3, 2)) 
#
#
#for element in it:
#    print(element.group())
#

#for element in it:
#    print(element.groups())
#
#

import re


pattern = "[\w_\.]+@\w+\.(com|edu|net)"

email = input("Enter an email address: \n")
if (re.search(pattern, email)):
	print(email + " is a valid email")
else:
	print(email + " is not a valid email")

pattern = "(\d\d\d)-(\d\d\d)-(\d\d\d)"

new_pattern = r"\1##\2##\3##"

user_input = input()

new_user_input=re.sub(pattern, new_pattern, user_input)

print(new_user_input)
