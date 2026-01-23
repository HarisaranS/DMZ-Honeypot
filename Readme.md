## pfSense-Protected DMZ Honeypot System

This project demonstrates the design and deployment of a virtualized network security lab featuring a DMZ-based honeypot protected by a pfSense firewall. The environment is built to simulate real-world attack scenarios and capture malicious activity for analysis.

The network uses pfSense to segment WAN, LAN, and DMZ interfaces, with NAT port forwarding and firewall rules configured to expose controlled services hosted on an Ubuntu honeypot server. The honeypot emulates vulnerable HTTP (8080), FTP (2121), and SSH (2222) services to attract attackers and log suspicious behavior.

The honeypot system captures:

- Brute-force login attempts
- Credential harvesting activity
- Malicious command execution
- Source IPs and timestamps

# Technologies Used

- pfSense Firewall
- Ubuntu Linux
- VirtualBox
- NAT & Port Forwarding
- DMZ Network Architecture
- Honeypot Services (HTTP, FTP, SSH)
