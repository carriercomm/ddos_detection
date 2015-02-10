#!/bin/bash

level="-L2"

echo -e "\033[1mTesting script for semestral project"
echo "Author: Jan Neuzil"
echo -e "neuzija1@fit.cvut.cz\033[0m\n"

if [ $# -ne 1 ]; then 
    echo -e "\033[1;31mError:  \033[0mBad arguments, usage: $0 DATA_FILE."
	exit 1
fi

echo -e "\033[1mInfo: \033[0mChecking for all required files, programs and permissions."
if ! [ -r $PWD -a -w $PWD -a -x $PWD ]; then
	echo -e "\033[1;31mError:  \033[0mYou do not have enough permissions in the current directory."
	exit 1
fi
command -v gnuplot >/dev/null 2>&1 || { echo -e "\033[1;31mWarning:  \033[0mGnuplot is not installed on this computer, text results only"; level="-L1"; }

if ! [ -f $PWD/ddos_detection ]; then
	echo -e "\033[1mInfo:  \033[0mCompiling DDoS detection program."
	make > /dev/null
fi

if ! [ -f $PWD/ddos_detection ]; then
	echo -e "\033[1;31mError:  \033[0mBinary file of the DDoS detection program is missing, compilation failed."
	exit 1
fi

echo -e "\033[1mInfo: \033[0mRunning DDoS detection."
./ddos_detection -d1 -e0 $level -w1800 -f $1

exit 0

