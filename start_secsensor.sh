#!/bin/sh

clear

echo 'Cleaning old processes...'
str=`ps -Af | grep secsensor.py &`
arr=($(echo $str))
pid=${arr[1]}
kill -9 $pid

str=`ps -Af | grep secsensor_enabler.py &`
arr=($(echo $str))
pid=${arr[1]}
kill -9 $pid

echo 'Done!'
echo 'Starting ...'
/usr/local/bin/python secsensor.py &
/usr/local/bin/python secsensor_enabler.py &
echo 'Done!'

