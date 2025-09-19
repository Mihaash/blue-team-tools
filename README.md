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





