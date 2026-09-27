## Setting up Obsidian for note taking

- Install Obsidian for the OS you are working on.
- ENSURE TO UTILIZE DIFFERENT FILES PER SCANNED MACHINE OR ENVIRONMENT. DO NOT WORK ON THE SAME FILES AS MUCH AS YOU CAN.

Example File Hierarchy:
```
- <VNET_1>
    - NMAP Scans
    - TODO
    - <HOSTNAME_Testing>
    - Testing Notes and Methodology
    - Findings
- <VNET_2>
    - NMAP Scans
    - TODO
    - <HOSTNAME_Testing>
    - Testing Notes and Methodology
    - Findings
- <VNET_3>
    - NMAP Scans
    - TODO
    - <HOSTNAME_Testing>
    - Testing Notes and Methodology
    - Findings
```

# INSTALLATION (for centralized server)

## WINDOWS (Tested on Windows 10)

- Install from [the web browser.](https://obsidian.md/download).
- Make a folder `obsidian_vault`
- Properties > Sharing > `Everyone` > Enter your credentials
- Create a network location with it as well. 
- Point your Obsidian vault into the shared folder.

## LINUX (Tested on Kali Linux)

- Install the .deb package from [the web browser.](https://obsidian.md/download).
- `sudo apt install -f ./obsidian_deb`

### On the server to Obsidian centrally (only on one system):

```
sudo mkdir -p /srv/obsidian-vault
sudo chown -R nobody:nogroup /srv/obsidian-vault
sudo chmod -R 0777 /srv/obsidian-vault

// restart
sudo systemctl restart smbd
```
```
/etc/samba/smb.conf:

[obsidian]
   path = /srv/obsidian-vault
   browseable = yes
   writable = yes
   guest ok = yes
   create mask = 0777
   directory mask = 0777
   oplocks = no
   level2 oplocks = no
```

# MOUNTING
### Mount from Linux:

```
mkdir -p ~/obsidian
mount -t cifs //server-ip/obsidian ~/obsidian, vers=3.0
```

### Mount from Windows:

- PowerShell (PS):
```
New-PSDrive -Name "O" -PSProvider FileSystem -Root "\\server-ip\obsidian" -Persist -Credential (Get-Credential)
```
- Through Network Discovery, identify the workstation hosting the share, connect to it.
- Install the Obsidian application and import the vault that is in the shared drive. 
- Work through that vault folder on your end, using. Files should automatically sync. 


### Compress to OneDrive or other shares

```
# Linux
zip -r obsidian_team_backup.zip ./

# Windows CMD
tar.exe -xf archive.zip

# Windows PowerShell
Compress-Archive \obsidian obsidian_team_backup.zip
```
