#!/bin/bash
BUILD="./build"

if [ $1 == "off" ]; then
	ip link set dev ens33 xdp off
	echo "remove old xdp program.."
elif [ $1 == "on" ]; then
	sudo ip link set dev ens33 xdp obj $BUILD/$2.o
	echo "set new xdp program.."
fi
