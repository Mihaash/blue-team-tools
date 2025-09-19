# blue-team-tools
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
@mihaash  nuclei -u http://saturn.picoctf.net:62605/                   

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.4.10

		projectdiscovery.io

[WRN] Found 1 templates with syntax error (use -validate flag for further examination)
[INF] Current nuclei version: v3.4.10 (latest)
[INF] Current nuclei-templates version: v10.2.8 (latest)
[INF] New templates added in latest release: 114
[INF] Templates loaded for current scan: 8323
[INF] Executing 8121 signed templates from projectdiscovery/nuclei-templates
[WRN] Loading 202 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] Templates clustered: 1782 (Reduced 1676 Requests)
[INF] Using Interactsh Server: oast.live
[INF] Scan completed in 3m. 0 matches found.
