#!/bin/bash

read -p "Enter the rows number " number


for i in `seq 1 $number`
do
	echo "-500 order by $i "
	echo "-500 order by $i # "
	echo "-500 order by $i -- - "

	echo "-500' order by $i "
	echo "-500' order by $i # "
	echo "-500' order by $i -- - "

done

