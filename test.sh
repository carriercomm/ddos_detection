#!/bin/bash

echo -e "\033[1mTesting script for semestral project"
echo "Author: Jan Neuzil"
echo -e "neuzija1@fit.cvut.cz\033[0m\n"

echo -e "\033[1mInfo: \033[0mChecking all files and permissions, preparing data files..."
if ! [ -r $PWD -a -w $PWD -a -x $PWD]; then
	echo -e "\033[1;31mError:  \033[0mYou do not have enough permissions in the current directory."
	exit 1
sleep 1

make

if ! [ -f $PWD/ddos_detection ]; then
	echo -e "\033[1;31mError:  \033[0mBinary file of the DDoS detection program is missing.\t\033[1m./gen/gen.c\033[0m"
	exit 1
fi

echo -e "\033[1mInfo: \033[0mRunning DDoS detection."
./ddos_detection -L2 -w1800 -f data/trace.txt

exit 0

