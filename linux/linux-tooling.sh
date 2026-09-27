#!/bin/bash
sudo apt update && sudo apt install git python3-venv -y

target_user=$(whoami)
mkdir -p ~/tools/ ~/tools/privesc

chown -R ${target_user}:${target_user} ~/tools/ ~/tools/privesc
chmod u+rwx ~/tools/ ~/tools/privesc

sudo -u ${target_user} git clone https://github.com/No4Sec/redteam-launcher.git ~/tools/privesc/redteam-launcher

python3 -m venv ~/tools/privesc/redteam-launcher/.venv
source ~/tools/privesc/redteam-launcher/.venv/bin/activate
python3 -m pip install colorama

sudo -u ${target_user} git clone https://github.com/AlessandroZ/BeRoot.git ~/tools/privesc/beroot

# make privesc tar
tmpdir=$(mktemp -d)
mkdir -p "$tmpdir/privesc/redteam-launcher" "$tmpdir/privesc/beroot"
cp -a ~/tools/privesc/redteam-launcher/launcher.py "$tmpdir/privesc/redteam-launcher/"
cp -ra ~/tools/privesc/redteam-launcher/scripts "$tmpdir/privesc/redteam-launcher/"
cp -ra ~/tools/privesc/redteam-launcher/.venv "$tmpdir/privesc/redteam-launcher/"
cp -ra ~/tools/privesc/beroot/Linux/* "$tmpdir/privesc/beroot/"
tar -C "$tmpdir" -cvf ~/tools/privesc/linux_privesc.tar privesc
rm -rf "$tmpdir"
