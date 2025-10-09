#!/bin/bash

# Get user context
who=$(whoami)
# Make tools directory
mkdir ~/tools
chown -R $who:$who ~/tools

# Cloud tools installation
mkdir -p ~/tools/cloud/
wget https://github.com/BishopFox/cloudfox/releases/download/v1.13.0/cloudfox-linux-amd64.zip -O /tmp/cloudfox-linux-amd64.zip
unzip /tmp/cloudfox-linux-amd64.zip -d ~/tools/cloud/