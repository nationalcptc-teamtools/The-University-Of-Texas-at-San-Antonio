#!/bin/bash

# List of IPs to exclude
OUT_OF_SCOPE_IPS=(
  "192.168.1.10"
  "203.0.113.25"
  "198.51.100.42"
)

# create blacklist list 
ipset create blacklist hash:ip hashsize 4096


# drop all connections with the said list
iptables -I INPUT  -m set --match-set blacklist src -j DROP 
iptables -I FORWARD  -m set --match-set blacklist src -j DROP 


# one by one, add the IPs or ranges
for IP in "${OUT_OF_SCOPE_IPS[@]}"; do
    ipset add blacklist "$IP"
done
