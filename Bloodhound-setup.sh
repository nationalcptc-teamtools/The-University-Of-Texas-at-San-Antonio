# Docker Install
mkdir BHCE
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  bookworm stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker run hello-world


# BloodHound Install
wget https://raw.githubusercontent.com/SpecterOps/BloodHound/refs/heads/main/examples/docker-compose/docker-compose.yml


# RustHound-CE Install
mkdir rhce
git clone https://github.com/g0h4n/RustHound-CE.git
cd RustHound-CE
curl https://sh.rustup.rs -sSf | sh # press enter here. After install close terminal and reopen
make release
sudo cp rusthound-ce /usr/bin/rusthound-ce

# BloodHound Py Install
git clone https://github.com/dirkjanm/BloodHound.py.git
