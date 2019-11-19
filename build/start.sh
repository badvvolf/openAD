#!/bin/bash

echo "Your network interface is..."

ifconfig

read -p "Choose interface: " interface

echo "Delete past data.."
sudo tc filter del dev $interface egress
sudo ./cleanmap -i ens33 -r

echo "Start core.."
sudo ./core

echo "Start honeyport..."
sudo ./module_honeyport

echo "Start honeyssh..."
sudo ./module_honeyssh
