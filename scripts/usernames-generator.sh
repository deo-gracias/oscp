#!/bin/bash

usage () {
	echo "usage: $0 [user list file]"
	echo "Simple script to generate usernames based on users list"
	exit 1
}

# did you specify a listener IP?
if [ $# -gt 1 ] || [ "$1" == "--help" ] ; then
   usage
fi

while IFS= read -r line
do
	first=$(echo $line | cut -d ' ' -f1 | tr '[:upper:]' '[:lower:]')
	i_first=${first:0:1}
	last=$(echo $line | cut -d ' ' -f2 | tr '[:upper:]' '[:lower:]')
	i_last=${last:0:1}

	str="$i_first$last\n"
	str+="$i_last$first\n"
  	str+="$first$last\n"
	str+="$last$first\n"
  	str+="$first""_""$last\n"
	str+="$last""_""$first\n"
  	str+="$first.$last\n"
	str+="$last.$first"

  	echo -e $str

done < "$1"