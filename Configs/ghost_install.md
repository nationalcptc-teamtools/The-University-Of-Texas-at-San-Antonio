
# Manual Guide to GhostWriter

- AFTER INITIAL SETUP, RUN THIS ON THE CENTRAL MACHINE THAT GHOSTWRITER SHOULD BE ON.
- ENSURE TO RUN THE `setup-script.sh` BEFORE RUNNING THIS SO THE TOOLS ARE IN PLACE. 
- OTHER MACHINES WILL ACCESS THIS THROUGH PORT FORWARDING:
    `sudo ssh -N -L 80:localhost:80 <user>@<IP_OF_GHOSTWRITER_MACHINE>`


# Installation

On your machine that will host Ghostwriter (make sure there is enough STORAGE):

```
sudo apt install -y \
	docker.io \
	docker-compose \
	openjdk-11-jdk
```

Install Ghostwriter:

```
mkdir ~/tools/ && cd ~/tools/
git clone https://github.com/GhostManager/Ghostwriter.git 
sudo ~/tools/Ghostwriter/ghostwriter-cli-linux install

# Get the admin password
~/tools/Ghostwriter/ghostwriter-cli-linux config get admin_password

# Ghostwriter now should run on https://localhost.
```

If you need to EXPLICITLY allow hosts to connect:
```
./ghostwriter-cli-linux config allowhost <YOUR DOMAIN NAME OR IP>
./ghostwriter-cli-linux containers down
./ghostwriter-cli-linux containers up
```

To change the admin password (do not unless you need to), first delete the docker volumes associated with Ghostwriter.
```
docker volumes
docker volume rm <insert_name>
```
Then, change the password and restart Ghostwriter containers:

```
./ghostwriter-cli-linux config set admin_password <insert_password>
./ghostwriter-cli-linux down
./ghostwriter-cli-linux up
```

Ghostwriter will be hosted at `https://localhost/` from the central machine.

Give your team this command to access Ghostwriter remotely:
`sudo ssh -N -L 80:localhost:80 user@<IP>`
