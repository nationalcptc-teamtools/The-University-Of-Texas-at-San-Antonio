#!/bin/bash

# setup-script.sh
#
# With <3 from the UTSA CPTC team
# Tested on:
# Kali 2023.4-vmware
# Linux kali 6.5.0-kali3-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.5.6-1kali1 (2023-10-09) x86_64 GNU/Linux


### !! INSTALL XTERM ON WINDOWS FIRST MANUALLY AND THEN IMPORT THE MOBA CONFIG. !!

#read -p "Please run this script using the bash command, inside the context of the bash shell. Enter \"/bin/bash\", then execute the script with \"bash setup-script.sh\""

# The basics
sudo apt install tmux -y

# tmux + zsh config changes
echo "export HISTSIZE=100000" >> ~/.zshrc
echo "export HISTFILESIZE=100000" >> ~/.zshrc
source ~/.zshrc
export DEBIAN_FRONTEND=noninteractive

# Get user context
who=$(whoami)

# Setting default shell to bash
#chsh -s /bin/bash $who

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
#sudo apt install -y kali-desktop-xfce xorg xrdp
#sudo systemctl enable xrdp --now
#sudo systemctl start xrdp

# Make tools directory
mkdir ~/tools
chown -R $who:$who ~/tools

# Peass-NG Suite
mkdir -p ~/tools/privesc/
cp /usr/share/peass/linpeas/linpeas.sh ~/tools/privesc
cp /usr/share/peass/winpeas/winPEASany.exe ~/tools/privesc



echo "Ok, done :) refresh your ssh connection or enter bash to continue - Happy Hacking!"