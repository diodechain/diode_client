#!/usr/bin/env bash

./diode_race_test config -list
./diode_race_test time

./diode_race_test -diodeaddrs asia.testnet.diode.io:41046 -e2e=false socksd > /dev/null & 

diode_pid=$!
echo "Start diode-cli pid: $diode_pid"

# check whether the diode socks start
# client should connect to valid network in 9 seconds
for i in 3
do
    res=$(lsof -i4:1080)
    if [ ${#res} -ge 5 ]
    then
        break
    fi
    res=$(lsof -i6:1080)
    if [ ${#res} -ge 5 ]
    then
        break
    fi
    sleep 3 
done

curl -v --socks5-hostname localhost:1080 pi-taipei.diode.link
ret=$?

kill -9 $diode_pid
echo "\nKill diode-cli"
rm ./diode_race_test

exit $ret