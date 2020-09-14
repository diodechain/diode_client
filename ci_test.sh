#!/usr/bin/env bash

./diode_race_test config -list
./diode_race_test time

./diode_race_test -diodeaddrs asia.testnet.diode.io:41046 -e2e=false socksd > /dev/null & 

diode_pid=$!
echo "Start diode-cli pid: $diode_pid and sleep 3 seconds"

sleep 3

curl -v --socks5-hostname localhost:1080 pi-taipei.diode.link
ret=$?

kill -9 $diode_pid
echo "\nKill diode-cli"
rm ./diode_race_test

exit $ret