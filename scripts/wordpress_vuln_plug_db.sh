#!/bin/bash

read -p 'Absolute path of file to write the update: ' file

rm $file
touch $file 

mkdir /tmp/test 2> /dev/null
cd /tmp/test
rm /tmp/test/*

searchsploit --color Wordpress | grep -i plugin | awk -F "webapps/" '{print $2}' | cut -d "." -f1 > /tmp/test/ids.txt

for i in $(cat /tmp/test/ids.txt)
do 
searchsploit -m $i > /dev/null

#echo $i
cat /tmp/test/$i* | grep "/wp-content/plugins" | sort -u | awk -F "/wp-content/plugins/" '{print $2}' | cut -d "/" -f1 | sort -u 2>&1 | tee -a $file
cat /tmp/test/$i* | grep "https://downloads.wordpress.org/plugin/" | sort -u | awk -F "https://downloads.wordpress.org/plugin/" '{print $2}' | cut -d "." -f1 | sort -u 2>&1 | tee -a $file
#read -p "Pause"
rm /tmp/test/$i*

done

sort $file | uniq | grep -o "[a-zA-Z0-9_-]*[a-zA-Z0-9_-]" | grep "\S" | sort -u > /tmp/test/temp
cat /tmp/test/temp | awk '{print "/wp-content/plugins/"$0}' > $file
rm /tmp/test/temp
