#!/bin/bash

password_file=passwords;

for i in $(cat passwords); do 
	steghide extract -sf h1dd3n.jpg -p $i;
done
