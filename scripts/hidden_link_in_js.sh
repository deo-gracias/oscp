#!/bin/bash

url=http://127.0.0.1:3000
proxy=http://127.0.0.1:8080

for i in $(python3.8 http_link_extractor.py $url | grep ".js" | grep -v "//")
do
curl -x $proxy $url/$i | js-beautify | grep -o "/[a-zA-Z/0-9]*" | sort -u | grep -v "//" >> hidden.txt
done
cat hidden.txt | sort -u > hidden_js.txt
rm hidden.txt

wfuzz -u $url/FUZZ -w hidden_js.txt -p 127.0.0.1:8080 --hc 401 -Z
