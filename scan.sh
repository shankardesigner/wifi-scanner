#!/usr/bin/env python

iwlist wlp0s20f3 scam > wifi-aps.txt

# scan for the connected devices along with their vendors if possible
arp-scan --interface=wlp0s20f3 192.168.100.0/24
