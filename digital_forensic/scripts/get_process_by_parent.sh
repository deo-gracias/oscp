#!/bin/bash

pslist_file="/tmp/hahaha"
vol_profile="WinXPSP2x86"
memory_dump="stuxnet.vmem"

for i in `cat $pslist_file | awk '{print $4}' | sort -u -n`
do
j=`cat $pslist_file | awk -v var=$i '$3==var {print $2}'`
echo "#### System with Parent $j (PID $i) ####"  2>&1 | tee -a process_by_parent.txt


k=`cat $pslist_file | awk -v var=$i '$4==var {print $3}'`

for m in $k
do 
python2.7 /opt/volatility/vol.py -f $memory_dump --profile=$vol_profile cmdline -p $m | grep  --color=never ":"  2>&1 | tee  /tmp/temp_pstree  | tee -a process_by_parent.txt
echo "" 2>&1 | tee  /tmp/temp_pstree  | tee -a process_by_parent.txt
done

cat /tmp/temp_pstree && rm  /tmp/temp_pstree

done

