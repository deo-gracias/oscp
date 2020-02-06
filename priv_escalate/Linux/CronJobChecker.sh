#!/bin/bash
#---------------------------------------------------------------------------------#
# Name       = Cron Job Checker                                                   #
# Author     = @ihack4falafel                                                     #
# Date       = 12/16/2017                                                         #
# Reference  = https://www.youtube.com/watch?v=K9DKULxSBK4                        #
# Usage      = chmod +x CronJobChecker.sh && ./CronJobChecker.sh                  #
#---------------------------------------------------------------------------------#

IFS=$'\n'

# Check list of running processes
old_proc=$(ps -aux  | grep -v "0:00" | awk '$4 > 0.0 {print $0}' )

# Look for newly created processes
while true; do
  new_proc=$(ps -aux  | grep -v "0:00" | awk '$4 > 0.0 {print $0}' )
  diff <(echo "$old_proc") <(echo "$new_proc") | grep [\<\>] 
  #sleep 1
  old_proc=$new_proc
done

