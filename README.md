**:lock: CyberGuardian Ultimate - Advanced Cybersecurity Suite**  
*Automated network scanning & vulnerability detection with real-time threat intelligence*  

:sparkles: **Features**:  
- **:globe_with_meridians: Multi-Target Scanning**: Auto-resolve domains to IPs & scan all endpoints  
- **:shield: Vulnerability Detection**: CVE correlation & Exploit-DB integration  
- **:bar_chart: Smart Reporting**: HTML/JSON reports with prioritized findings  
- **:zap: Real-Time Monitoring**: Progress tracking with Enter-key updates  
- **:arrows_counterclockwise: Auto-Update**: Seamless GitHub integration for latest features  

**:rocket: Ideal For**:  
- Penetration testers  
- System administrators  
- Bug bounty hunters  
- Security researchers

**:hammer_and_wrench: Installation**:
```bash
sudo apt install nmap git
pip install -r requirements.txt
```

**:8ball: Basic Usage**:
```bash
# Basic scan with HTML or JSON report
python3 main.py example.com -o/--output html/json

# Deep scan with HTML or JSON report
python3 main.py example.com -m/--mode fast/deep -o/--ouput html/json

# Force update check
python3 main.py -u/--update
```

*Star :star: to support development | Contribute :tools: to enhance features*  

*(Python | Nmap | Exploit-DB | CVE Mitre integrated)*
