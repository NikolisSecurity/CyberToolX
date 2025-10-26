# 🚀 CyberGuardian Ultimate v2.0 - Quick Reference

## Start the Tool
```bash
cd /workspace/cmh8969s900cor7i3v4rbn8n9/CyberToolX
python3 main.py
```

## Most Useful Commands

### Target Management
```bash
target example.com           # Set target domain
target https://example.com   # Set target with HTTPS
showtarget                   # Show current target
cleartarget                  # Clear target
```

### Network Analysis (All Working ✅)
```bash
dnsenum        # Complete DNS enumeration (A, AAAA, MX, NS, TXT, SOA)
subdomain      # Find subdomains (www, mail, ftp, admin, api, etc.)
whois          # WHOIS lookup
reverse        # Reverse DNS lookup
dnszone        # Check for DNS zone transfer vulnerability
```

### Web Security Testing (All Working ✅)
```bash
headerscan     # Analyze 7 critical security headers
sslscan        # SSL/TLS configuration & certificate check
wafscan        # Detect WAF/CDN (Cloudflare, Akamai, AWS, etc.)
cmsscan        # Identify CMS (WordPress, Joomla, Drupal, etc.)
robots         # Check robots.txt and sitemap.xml
```

### OSINT Tools (All Working ✅)
```bash
emailharvest   # Extract email addresses from website
social         # Find social media links
metadata       # Extract page metadata
techstack      # Detect technology stack (frameworks, libraries)
```

### Basic Recon (Working ✅)
```bash
ping           # ICMP ping test
traceroute     # Trace route to target
```

### Port Scanning (Requires python-nmap)
```bash
quickscan      # Quick scan of top 100 ports
deepscan       # Deep scan of all 65535 ports
servicescan    # Service version detection
vulnscan       # Vulnerability scanning with NSE scripts
```

### Utility Commands
```bash
help           # Show all commands
results        # View scan results
clear          # Clear screen
about          # About the tool
exit           # Exit (or 'quit')
```

## Example Workflows

### Quick Website Security Audit
```bash
cyber@guardian > target https://example.com
cyber@guardian > headerscan
cyber@guardian > sslscan
cyber@guardian > wafscan
cyber@guardian > cmsscan
cyber@guardian > results
```

### Network Reconnaissance
```bash
cyber@guardian > target example.com
cyber@guardian > dnsenum
cyber@guardian > subdomain
cyber@guardian > whois
cyber@guardian > dnszone
cyber@guardian > results
```

### OSINT Investigation
```bash
cyber@guardian > target https://target.com
cyber@guardian > emailharvest
cyber@guardian > social
cyber@guardian > metadata
cyber@guardian > techstack
cyber@guardian > results
```

### Full Security Scan (if nmap installed)
```bash
cyber@guardian > target scanme.nmap.org
cyber@guardian > ping
cyber@guardian > quickscan
cyber@guardian > servicescan
cyber@guardian > vulnscan
cyber@guardian > results
```

## Pro Tips

### Auto-Correction
Made a typo? The tool will suggest corrections:
```bash
cyber@guardian > heeaderscan
Did you mean: headerscan?
[y/n]: y
✓ Using: headerscan
```

### Switching Targets
Change targets anytime without restarting:
```bash
cyber@guardian [target1.com] > target target2.com
✓ Target set to: target2.com
cyber@guardian [target2.com] >
```

### Multiple Scans
Run multiple scans on the same target:
```bash
cyber@guardian > target example.com
cyber@guardian > dnsenum
cyber@guardian > headerscan
cyber@guardian > wafscan
cyber@guardian > results    # See all results aggregated
```

### View All Commands
```bash
cyber@guardian > help
# Shows comprehensive list organized by category
```

## Output Color Coding

- 🟢 **Green** - Success, working features, valid data
- 🔴 **Red** - Errors, vulnerabilities, missing security features
- 🟡 **Yellow** - Warnings, potential issues, informational
- 🔵 **Cyan** - System messages, categories, helpful hints

## Quick Troubleshooting

### "python-nmap not installed"
```bash
# For port scanning tools only
pip3 install python-nmap
sudo apt install nmap
```

### "No target set"
```bash
# Set a target first
cyber@guardian > target example.com
```

### "Command not found"
```bash
# Check spelling or use help
cyber@guardian > help
```

## Status Summary

| Feature | Status |
|---------|--------|
| Interactive menu | ✅ Working |
| Auto-correction | ✅ Working |
| Loading animation | ✅ Working |
| DNS tools | ✅ Working (5/5) |
| Web security tools | ✅ Working (5/5) |
| OSINT tools | ✅ Working (4/4) |
| Basic recon | ✅ Working (2/2) |
| Port scanning | ⚠️ Requires nmap |
| Results tracking | ✅ Working |

**25+ commands ready to use out of the box!**

---

**Happy Hacking! 👾🛡️**

*Remember: Only use on systems you own or have explicit permission to test.*
