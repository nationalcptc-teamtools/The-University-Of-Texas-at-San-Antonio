#!/bin/bash

# setup-script.sh
#
# With <3 from the UTSA CPTC team
# Tested on:
# Kali 2023.4-vmware
# Linux kali 6.5.0-kali3-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.5.6-1kali1 (2023-10-09) x86_64 GNU/Linux

read -p "Please run this script using the bash command, inside the context of the bash shell. Enter \"/bin/bash\", then execute the script with \"bash setup-script.sh\""

# The basics
sudo apt install tmux -y

# tmux + zsh config changes
echo "export HISTSIZE=100000" >> ~/.bashrc
echo "export HISTFILESIZE=100000" >> ~/.bashrc
source ~/.bashrc
export DEBIAN_FRONTEND=noninteractive

# Get user context
who=$(whoami)

# Setting default shell to bash
chsh -s /bin/bash $who

# Before we install tools, let's change/update our repos
sudo apt update -y

# Install tools (apt)
sudo apt install -y \
	apt-transport-https \
	pacu \
	peass \
 	awscli \
	sliver \
	python3 \
	python3-pip \
	libssl-dev \
	seclists \
	curl \
	gobuster \
	nbtscan \
	nikto \
	onesixtyone \
	enum4linux \
	smbmap \
	smtp-user-enum \
	sslscan \
	hashcat \
	sqlmap \
	john


# XRDP lol
sudo apt install -y kali-desktop-xfce xorg xrdp
sudo systemctl enable xrdp --now
sudo systemctl start xrdp

# Make tools directory
mkdir ~/tools
chown -R $who:$who ~/tools

# Cloud tools installation
mkdir -p ~/tools/cloud/
wget https://github.com/BishopFox/cloudfox/releases/download/v1.13.0/cloudfox-linux-amd64.zip -O /tmp/cloudfox-linux-amd64.zip
unzip /tmp/cloudfox-linux-amd64.zip -d ~/tools/cloud/



# Peass-NG Suite
mkdir -p ~/tools/privesc/
cp /usr/share/peass/linpeas/linpeas.sh ~/tools/privesc
cp /usr/share/peass/winpeas/winPEASany.exe ~/tools/privesc
wget -4 https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1 -O ~/tools/privesc/PowerUp.ps1

# PowerView + Pywerview
mkdir -p ~/tools/AD/
wget -4 https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 -O ~/tools/AD/PowerView.ps1
mkdir -p ~/tools/AD/Pywerview/
git clone https://github.com/aniqfakhrul/powerview.py.git ~/tools/AD/Pywerview/
chmod +x ~/tools/AD/Pywerview/setup.py
chmod +x ~/tools/AD/Pywerview/powerview.py
pip3 install -r ~/tools/AD/Pywerview/requirements.txt
sudo python3 ~/tools/AD/Pywerview/setup.py install
# Can't believe I had to do this... >_>
sudo cp /usr/local/lib/python3.11/dist-packages/gnureadline-8.1.2-py3.11-linux-x86_64.egg/gnureadline.libs/libncurses-a6f90868.so.5.9 /usr/lib/x86_64-linux-gnu/
sudo cp /usr/local/lib/python3.11/dist-packages/gnureadline-8.1.2-py3.11-linux-x86_64.egg/gnureadline.libs/libtinfo-10270e32.so.5.9 /usr/lib/x86_64-linux-gnu/

# SharpHound collector
mkdir -p ~/tools/AD/SharpHound/
wget https://github.com/BloodHoundAD/SharpHound/releases/download/v2.3.0/SharpHound-v2.3.0.zip -O /var/tmp/SharpHound-v2.3.0.zip
7z x -o"$HOME/tools/AD/SharpHound/" /var/tmp/SharpHound-v2.3.0.zip

# Certipy / Certify
pip3 install certipy-ad
sudo mv /usr/bin/certipy-ad /usr/bin/certipy
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe -O ~/tools/AD/Certify.exe

# Rubeus
mkdir -p ~/tools/AD/Rubeus/
wget -4 https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe -O ~/tools/AD/Rubeus/Rubeus.exe
wget -4 "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/dotnet%20v4.7.2%20compiled%20binaries/Rubeus.exe" -O ~/tools/AD/Rubeus/Rubeus-4_7_2.exe
wget -4 "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/dotnet%20v4.5%20compiled%20binaries/Rubeus.exe" -O ~/tools/AD/Rubeus/Rubeus-4_5.exe
wget -4 "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/dotnet%20v3.5%20compiled%20binaries/Rubeus.exe" -O ~/tools/AD/Rubeus/Rubeus-3_5.exe

# Mimikatz
mkdir -p ~/tools/cred_harvesting
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe ~/tools/cred_harvesting

# Removed C2 folder, itz on path now.

# Removed sublime text, we're not normies
#
echo "Ok, done :) refresh your ssh connection or enter bash to continue - Happy Hacking!"
