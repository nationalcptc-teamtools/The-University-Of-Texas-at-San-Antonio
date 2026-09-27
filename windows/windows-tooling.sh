#!/bin/bash

# Get user context
who=$(whoami)
# Make tools directory
mkdir ~/tools
chown -R $who:$who ~/tools

# PowerView + Pywerview
#mkdir -p ~/tools/AD/
#wget -4 https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 -O ~/tools/AD/PowerView.ps1
#mkdir -p ~/tools/AD/Pywerview/
#git clone https://github.com/aniqfakhrul/powerview.py.git ~/tools/AD/Pywerview/
#chmod +x ~/tools/AD/Pywerview/setup.py
#chmod +x ~/tools/AD/Pywerview/powerview.py
#pip3 install -r ~/tools/AD/Pywerview/requirements.txt
#sudo python3 ~/tools/AD/Pywerview/setup.py install
# Can't believe I had to do this... >_>
sudo cp /usr/local/lib/python3.11/dist-packages/gnureadline-8.1.2-py3.11-linux-x86_64.egg/gnureadline.libs/libncurses-a6f90868.so.5.9 /usr/lib/x86_64-linux-gnu/
sudo cp /usr/local/lib/python3.11/dist-packages/gnureadline-8.1.2-py3.11-linux-x86_64.egg/gnureadline.libs/libtinfo-10270e32.so.5.9 /usr/lib/x86_64-linux-gnu/

# Certipy / Certify
pip3 install certipy-ad
sudo mv /usr/bin/certipy-ad /usr/bin/certipy
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe -O ~/tools/AD/Certify.exe

# SharpHound collector
mkdir -p ~/tools/AD/SharpHound/
wget https://github.com/BloodHoundAD/SharpHound/releases/download/v2.3.0/SharpHound-v2.3.0.zip -O /var/tmp/SharpHound-v2.3.0.zip
7z x -o"$HOME/tools/AD/SharpHound/" /var/tmp/SharpHound-v2.3.0.zip

# Mimikatz
mkdir -p ~/tools/cred_harvesting
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe ~/tools/cred_harvesting

# Rubeus
mkdir -p ~/tools/AD/Rubeus/
wget -4 https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe -O ~/tools/AD/Rubeus/Rubeus.exe
wget -4 "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/dotnet%20v4.7.2%20compiled%20binaries/Rubeus.exe" -O ~/tools/AD/Rubeus/Rubeus-4_7_2.exe
wget -4 "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/dotnet%20v4.5%20compiled%20binaries/Rubeus.exe" -O ~/tools/AD/Rubeus/Rubeus-4_5.exe
wget -4 "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/dotnet%20v3.5%20compiled%20binaries/Rubeus.exe" -O ~/tools/AD/Rubeus/Rubeus-3_5.exe
