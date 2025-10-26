# 📦 CyberGuardian Ultimate v2.0 - Installation Guide

## Quick Start

### 1. See the Demo First!

```bash
python3 demo.py
```

This shows you the interface and features without requiring any dependencies.

---

## Full Installation

### Step 1: Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y nmap whois traceroute dnsutils python3-pip
```

**Fedora/RHEL:**
```bash
sudo dnf install -y nmap whois traceroute bind-utils python3-pip
```

**macOS:**
```bash
brew install nmap
```

### Step 2: Install Python Dependencies

**Option A: All at once**
```bash
pip3 install -r requirements.txt
```

**Option B: Individual packages**
```bash
pip3 install termcolor requests beautifulsoup4 python-nmap pyyaml dnspython lxml
```

**If you get permission errors:**
```bash
pip3 install --user -r requirements.txt
```

Or use a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 3: Launch CyberGuardian

```bash
python3 main.py
```

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'X'"

**Solution:** Install the missing module
```bash
pip3 install X
```

### "nmap: command not found"

**Solution:** Install nmap system package
```bash
sudo apt install nmap    # Ubuntu/Debian
sudo dnf install nmap    # Fedora/RHEL
brew install nmap        # macOS
```

### "Permission denied" during scans

**Solution:** Some scans require root privileges
```bash
sudo python3 main.py
```

### Imports work but tool crashes

**Solution:** Check Python version (requires 3.8+)
```bash
python3 --version
```

If < 3.8, upgrade Python or use pyenv.

---

## Minimal Installation (Core Features Only)

If you only want basic features without all dependencies:

```bash
pip3 install termcolor requests python-nmap
```

This gives you:
- Interactive interface
- Port scanning
- Basic reconnaissance
- Target management

---

## Docker Installation (Coming Soon)

```bash
docker pull cyberguardian/ultimate:v2.0
docker run -it cyberguardian/ultimate
```

---

## Verification

Test your installation:

```bash
python3 -c "from utils.menu_system import MenuSystem; print('✓ Installation successful!')"
```

---

## What's Included

After installation, you'll have access to:

- ✅ 60+ security tools
- ✅ Interactive menu interface
- ✅ Auto-correction
- ✅ Beautiful ASCII art
- ✅ Real-time progress tracking
- ✅ Multi-format reporting (HTML, JSON, CSV, XML)
- ✅ OSINT capabilities
- ✅ Web security testing
- ✅ Network analysis

---

## Support

- **Issues:** https://github.com/NikolisSecurity/CyberToolX/issues
- **Demo:** Run `python3 demo.py`
- **Docs:** See README.md

---

**Happy Hacking! 👾🛡️**
