#!/bin/bash

# List of IPs to exclude
OUT_OF_SCOPE_IPS=(
  "192.168.1.10"
  "203.0.113.25"
  "198.51.100.42"
  "10.10.10.1/24"
)


# one by one, add the IPs or ranges
for IP in "${OUT_OF_SCOPE_IPS[@]}"; do
    iptables -I INPUT -s "$IP" -j DROP
    iptables -I OUTPUT -d "$IP" -j DROP
done
