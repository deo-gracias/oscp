import re
pattern = re.compile("\$_(GET|POST)\[[\'\"]\w+[\'\"]\]")


for i, line in enumerate(open('/tmp/sample.txt')):
    for match in re.finditer(pattern, line):
        print('Found on line %s: %s' % (i+1, match.group()))
