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

# Install system dependencies (minimal)
sudo apt update
sudo apt install dnsutils -y

# Install Python dependencies
pip3 install -r requirements.txt

# Launch NPS Tool
python3 main.py
```

---

## 🚀 Quick Start

### Launch the Tool
```bash
python3 main.py
```

You'll see a loading screen with web security module initialization, then the main interface:

```
╒═════════════════════╕
│ Account Information │
│ Target: Not Set     │
│ IP: 203.0.113.45    │
╘═════════════════════╛

══╦═════════════════════════════════════╦══
╔════════════════════════════════════════╗
│  NPS Tool                              │
│  Advanced Web Security Testing         │
╚════════════════════════════════════════╝

Hello @username. Welcome to NPS Tool
To view the list of commands, type help

[>]
```

### Basic Workflow

```bash
# 1. Set your target
[>] target example.com

✓ Target set to: example.com

# 2. Run web security scans
[>] headerscan
[>] sslscan
[>] wafscan

# 3. Enumerate subdomains
[>] subdomain

# 4. View results
[>] results

# 5. Exit
[>] exit
```

---

## 📚 Command Reference

### Main Commands

| Command | Description |
|---------|-------------|
| `help` | Display all available commands with descriptions |
| `clear` | Clear the screen |
| `banner` | Display the main banner |
| `about` | About NPS Tool |
| `exit` / `quit` | Exit the application |

### Target Management

| Command | Description | Example |
|---------|-------------|---------|
| `target <host>` | Set target for scanning | `target example.com` |
| `showtarget` | Display current target | `showtarget` |
| `cleartarget` | Clear current target | `cleartarget` |

### Web Testing (13 tools)

- `webscan` - Complete web scan (placeholder)
- `headerscan` - Security headers analysis
- `sslscan` - SSL/TLS analysis
- `wafscan` - WAF detection
- `cmsscan` - CMS detection
- `robots` - robots.txt check
- `dirscan` - Directory enumeration (placeholder)
- `apiscan` - API discovery (placeholder)
- `sqlmap` - SQL injection (placeholder)
- `xsstest` - XSS testing (placeholder)
- `csrftest` - CSRF testing (placeholder)
- `graphql` - GraphQL testing (placeholder)
- `jwtscan` - JWT analysis (placeholder)

### DNS & Subdomain (2 tools)

- `dnsenum` - DNS enumeration
- `subdomain` - Subdomain discovery

### Web OSINT (3 tools)

- `emailharvest` - Email harvesting
- `metadata` - Metadata extraction
- `techstack` - Technology detection

### Reporting & Analytics (9 tools)

- `results` - Show all results
- `report` - Generate report (placeholder)
- `export` - Export to file (placeholder)
- `history` - Scan history (placeholder)
- `compare` - Compare scans (placeholder)
- `stats` - Usage statistics
- `timeline` - Command timeline
- `performance` - Performance metrics
- `exportstats` - Export analytics

---

## 🎯 Usage Examples

### Example 1: Quick Web Audit

```bash
python3 main.py

[>] target https://example.com
[>] headerscan
[>] sslscan
[>] wafscan
[>] cmsscan
[>] results
```

### Example 2: Comprehensive Web Assessment

```bash
[>] target company.com
[>] dnsenum
[>] subdomain
[>] techstack
[>] emailharvest
[>] robots
[>] stats
```

---

## 🎨 Features Showcase

### Auto-Correction

```bash
[>] hel

Command "hel" is not valid.
Did you mean: help?
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
