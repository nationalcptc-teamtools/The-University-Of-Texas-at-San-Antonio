# INITIAL ENUMERATION STEPS FOR ALL MACHINES

When you get access to your machine, we will assign CIDR ranges to each person and these will be ran locally on your jumpbox machine.

DO NOT SCAN ANY OT NETWORK IPs, TRIPLE CHECK TO ENSURE THE RANGES DO NOT INCLUDE OT OR ANY OUT-OF-SCOPE ELEMENTS.

### Ping Sweep

Ensure to exclude the OT subnet by creating an `exclude_ot.txt` file. DO NOT SCAN THE OT SUBNET WITH THESE COMMANDS.

To be safe, run the `iptables.sh` script after updating it with the out-of-scope IPs.

Put the live IPs into a list OR use the subnet itself:

`nmap -sn 192.168.1.0/24 --open --exclude-file exclude_ot.txt -oG subnet_1.gnmap`
`cat subnet_1.gnmap | grep "Up" | cut -d " " -f2 > live_hosts_<subnet>.txt`

If we get a big subnet like /16s, always a good idea to run a `masscan` to identify LIVE HOSTS and then feed them into service scans next.
EXCLUDE OT AND OTHER OUT-OF-SCOPE ITEMS.

`masscan 10.0.0.1/24 --excludeFile <file> --rate 10000 --open-only -oL output.txt`

### Service and Port Scans

Ensure to exclude the OT subnet by creating an `exclude_ot.txt` file.

With the live IPs identified, run service AND port scans and save output. COPY and PASTE the scan output with open ports and services into the OBSIDIAN NOTES | GOOGLE DOC with filename format: `<IP>.nmap`

`nmap -iL live_hosts_<subnet>.txt -p- --open -sV -T4 -oN detailed_scan_<subnet>`

### Version and Vulnerability Checks

In addition to automatic checks, manually search service and OS version numbers.

`nmap -sV --script=vuln,vulners --open -p <ports> <target>`
`searchsploit "<Product> <version>"`

### UDP Scans

Run these to make sure we are not missing any protocols (top ports mainly):

`sudo nmap -sU --top-ports 100 -T4 -v -iL <live_hosts> -oN nmap_udp_<subnet>`

### Web Screenshotting Tools

Using tools like `aquatone` or `EyeWitness` it can be very easy to compile web screenshots and try out default credentials in an automated way. Once you have a list of web ports/IPs that can be extracted from `nmap` output, consider feeding them into a screenshotting tool to get a report:

EyeWitness:
`sudo ./EyeWitness.py -x /path/to/nmap.xml --web ---threads 10 --timeout 30 --headless -d /path/to/screens`






