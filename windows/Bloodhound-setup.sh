# You must install gnome-terminal to enable terminal access from Docker Desktop
sudo apt update
sudo apt install gnome-terminal

# Uninstall all conflicting packages
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do sudo apt-get remove $pkg; done

mkdir ~/BloodHoundCE
cd ~/BloodHoundCE
sudo apt-get update -y
sudo apt-get install ca-certificates curl -y
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  bookworm stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
sudo systemctl start docker
sudo docker run hello-world

# BloodHound Install
wget https://raw.githubusercontent.com/SpecterOps/BloodHound/refs/heads/main/examples/docker-compose/docker-compose.yml

# BloodHound Py Install
git clone https://github.com/dirkjanm/BloodHound.py.git

# RustHound CE Install
git clone https://github.com/g0h4n/RustHound-CE.git
cd RustHound-CE
curl https://sh.rustup.rs -sSf | sh
. "$HOME/.cargo/env"
make release
sudo cp rusthound-ce /usr/bin/rusthound-ce