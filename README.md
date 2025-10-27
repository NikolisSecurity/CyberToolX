# 🌐 NPS Tool v1.0

**Network Pentesting Suite - Web Security Edition**

[![Version](https://img.shields.io/badge/version-1.0-blue.svg)](https://github.com/NikolisSecurity/CyberToolX)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-Authorized%20Use%20Only-red.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-working-brightgreen.svg)](#)

> *Specialized web application security testing platform with 20+ web-focused security tools*

---

## 🚀 Quick Start

```bash
cd /workspace/cmh8969s900cor7i3v4rbn8n9/CyberToolX
python3 main.py
```

**That's it!** The tool works out of the box with 20+ commands ready to use.

### Example Session
```bash
[>] target example.com
✓ Target set to: example.com

[>] dnsenum
# DNS enumeration results...

[>] headerscan
# Security headers analysis...

[>] help
# Shows all available web security commands
```

---

## ⚡ Features

### 🎨 **Beautiful Interactive Interface**
- **Compact box-drawing style banner** with account information
- **Command auto-correction** - never type a command wrong again
- **Colorful terminal interface** with clean aesthetics
- **Real-time progress indicators** for all scans
- **Multi-target management** - switch between targets seamlessly

### 🔍 **20+ Web Security Tools**

#### 🌐 **Web Application Testing**
- Security Headers Analysis (HSTS, CSP, X-Frame-Options, etc.)
- SSL/TLS Configuration Scanning
- Certificate Analysis & Expiry Checking
- WAF/CDN Detection (Cloudflare, Akamai, AWS, F5, etc.)
- CMS Detection (WordPress, Joomla, Drupal, etc.)
- robots.txt & sitemap.xml Analysis
- Technology Stack Detection
- API Endpoint Discovery
- SQL Injection Testing (placeholder)
- XSS Testing (placeholder)
- CSRF Testing (placeholder)
- GraphQL Testing (placeholder)
- JWT Analysis (placeholder)

#### 🔍 **DNS & Subdomain**
- DNS Enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
- Subdomain Discovery (30+ common subdomains)

#### 🕵️ **Web OSINT**
- Email Harvesting from websites
- Metadata Extraction from web pages
- Technology Fingerprinting

#### 📊 **Reporting & Analysis**
- Scan Results Display
- Report Generation
- Export to File
- Scan History
- Result Comparison
- Analytics & Performance Tracking

---

## 📦 Installation

### Requirements
- **Python 3.8+**
- **nmap** (system package)
- **Linux/Unix** (recommended) or macOS

### Quick Install

```bash
# Clone repository
git clone https://github.com/NikolisSecurity/CyberToolX.git
cd CyberToolX

# Install system dependencies
sudo apt update
sudo apt install nmap whois traceroute dnsutils -y

# Install Python dependencies
pip3 install -r requirements.txt

# Launch CyberGuardian
python3 main.py
```

---

## 🚀 Quick Start

### Launch the Tool
```bash
python3 main.py
```

You'll see a beautiful loading screen, then the main interface:

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    ULTIMATE CYBER WARFARE PLATFORM v2.0                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Type 'help' for available commands | Type 'exit' to quit

cyber@guardian [no target] >
```

### Basic Workflow

```bash
# 1. Set your target
cyber@guardian [no target] > target scanme.nmap.org

✓ Target set to: scanme.nmap.org

# 2. Run a quick scan
cyber@guardian [scanme.nmap.org] > quickscan

# 3. Check for vulnerabilities
cyber@guardian [scanme.nmap.org] > vulnscan

# 4. View results
cyber@guardian [scanme.nmap.org] > results

# 5. Exit
cyber@guardian [scanme.nmap.org] > exit
```

---

## 📚 Command Reference

### Main Commands

| Command | Description |
|---------|-------------|
| `help` | Display all available commands with descriptions |
| `clear` | Clear the screen |
| `banner` | Display the main banner |
| `about` | About CyberGuardian Ultimate |
| `exit` / `quit` | Exit the application |

### Target Management

| Command | Description | Example |
|---------|-------------|---------|
| `target <host>` | Set target for scanning | `target example.com` |
| `showtarget` | Display current target | `showtarget` |
| `cleartarget` | Clear current target | `cleartarget` |

### Reconnaissance (12 tools)

- `quickscan` - Quick scan of top 100 ports
- `deepscan` - Deep scan of all 65535 ports
- `servicescan` - Service version detection
- `vulnscan` - Vulnerability scanning
- `nmap` - Advanced nmap options
- `ping` - ICMP ping test
- `traceroute` - Trace route to target
- `portscan` - Full port scanning
- `portsweep` - Multiple host sweep

### Network Analysis (9 tools)

- `dnsenum` - DNS enumeration
- `subdomain` - Subdomain discovery
- `dnszone` - DNS zone transfer
- `whois` - WHOIS lookup
- `reverse` - Reverse DNS
- `geoip` - Geolocation

### Web Testing (13 tools)

- `webscan` - Complete web scan
- `headerscan` - Security headers
- `sslscan` - SSL/TLS analysis
- `wafscan` - WAF detection
- `cmsscan` - CMS detection
- `robots` - robots.txt check
- `dirscan` - Directory enum
- `apiscan` - API discovery
- `sqlmap` - SQL injection
- `xsstest` - XSS testing

### OSINT (7 tools)

- `emailharvest` - Email harvesting
- `social` - Social media links
- `metadata` - Metadata extraction
- `techstack` - Technology detection
- `breach` - Breach checking
- `peoplesearch` - People OSINT

### Results (5 tools)

- `results` - Show all results
- `report` - Generate report
- `export` - Export to file
- `history` - Scan history
- `compare` - Compare scans

---

## 🎯 Usage Examples

### Example 1: Quick Web Audit

```bash
python3 main.py

cyber@guardian [no target] > target https://example.com
cyber@guardian [https://example.com] > quickscan
cyber@guardian [https://example.com] > headerscan
cyber@guardian [https://example.com] > sslscan
cyber@guardian [https://example.com] > results
```

### Example 2: Network Assessment

```bash
cyber@guardian [no target] > target company.com
cyber@guardian [company.com] > dnsenum
cyber@guardian [company.com] > subdomain
cyber@guardian [company.com] > deepscan
cyber@guardian [company.com] > vulnscan
cyber@guardian [company.com] > report
```

---

## 🎨 Features Showcase

### Auto-Correction

```bash
cyber@guardian [target] > quckscan

Did you mean: quickscan?
[y/n]: y
✓ Using: quickscan
```

### Beautiful Output
- ✅ Green for success
- ⚠️ Yellow for warnings
- ❌ Red for errors
- 💡 Cyan for info

---

## 🛡️ Legal Disclaimer

**⚠️ AUTHORIZED USE ONLY**

This tool is for **AUTHORIZED SECURITY TESTING ONLY**.

- ✅ Use on systems you own
- ✅ Use with written permission
- ❌ NEVER use without authorization

**Unauthorized access is illegal. Users are responsible for their actions.**

---

## 🚀 What's New in v2.0

- ✨ Interactive menu system
- 🎨 Beautiful ASCII art & loading screens
- 🔧 Auto-correction for commands
- 📊 60+ security tools
- 🎯 Multi-target management
- 📈 Real-time progress tracking
- 🌈 Colorful cyberpunk theme
- 📝 Enhanced reporting

---

**Stay Safe. Stay Ethical. Happy Hacking! 👾🛡️**
