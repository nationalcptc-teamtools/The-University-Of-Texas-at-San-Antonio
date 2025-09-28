#!/bin/bash

# List of IPs to exclude (whitelist)
OUT_OF_SCOPE_IPS=(
  "192.168.1.10"
  "203.0.113.25"
  "198.51.100.42"
)

# Flush existing rules (optional)
# iptables -F

# Apply whitelist rules
for IP in "${OUT_OF_SCOPE_IPS[@]}"; do
    echo "Whitelisting $IP..."
    iptables -I INPUT -s "$IP" -j ACCEPT
    iptables -I OUTPUT -d "$IP" -j ACCEPT
done

echo "Done. Out-of-scope IPs have been excluded."
