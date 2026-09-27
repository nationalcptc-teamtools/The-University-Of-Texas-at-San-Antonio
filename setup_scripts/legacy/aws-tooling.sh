#!/bin/bash
# PASS 1 as args for non kali
# run as sudo
#source zsh after running on kali
apt update
if [ "$1" == '' ]; then
    apt install -y python3 python3-pip pipx unzip python3-awscrt python3-jmespath awscli pacu
    echo -e '\nexport PATH=/usr/local/bin/:$PATH\nautoload bashcompinit && bashcompinit\nautoload -Uz compinit && compinit\ncomplete -C "/usr/local/bin/aws_completer" aws' >> ~/.zshrc
    echo "run source ~/.zshrc"
fi
if [ "$1" == '1' ]; then
    apt install -y python3 python3-pip pipx unzip python3-awscrt python3-jmespath
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    bash ./aws/install
    pipx install git+https://github.com/RhinoSecurityLabs/pacu.git
    pipx ensurepath
    echo -e '\n# AWS CLI v2 Config\nexport PATH=/usr/local/bin:$PATH\ncomplete -C "/usr/local/bin/aws_completer" aws' >> ~/.bashrc
    source ~/.bashrc
fi
