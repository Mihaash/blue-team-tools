  # blue-team-tools
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



| Feature      | Nessus                     | Nexpose (Rapid7)           |
| ------------ | -------------------------- | -------------------------- |
| Vendor       | Tenable                    | Rapid7                     |
| Target       | Vulnerability scanning     | Vulnerability + risk mgmt  |
| Integration  | Mostly scanning            | Integrates with Metasploit |
| Reporting    | Reports only               | Dashboards + reports       |
| Free version | Nessus Essentials (16 IPs) | Community (limited)        |


