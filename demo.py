#!/usr/bin/env python3
"""
CyberGuardian Ultimate v2.0 - Demo
Shows the interactive interface and features
"""

import sys
import time

# Simple colored output without termcolor
class Color:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def colored(text, color):
    colors = {
        'cyan': Color.CYAN,
        'green': Color.GREEN,
        'yellow': Color.YELLOW,
        'red': Color.RED
    }
    return f"{colors.get(color, '')}{Color.BOLD}{text}{Color.END}"

# Show banner
banner = f"""
{colored('╔═══════════════════════════════════════════════════════════════════════════════╗', 'cyan')}
{colored('║                                                                               ║', 'cyan')}
{colored('║   ██████╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗  ║', 'cyan')}
{colored('║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗ ║', 'cyan')}
{colored('║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ███╗██║   ██║███████║██████╔╝ ║', 'cyan')}
{colored('║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗ ║', 'cyan')}
{colored('║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║ ║', 'cyan')}
{colored('║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ║', 'cyan')}
{colored('║                                                                               ║', 'cyan')}
{colored('║              ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗  ║', 'cyan')}
{colored('║              ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝  ║', 'cyan')}
{colored('║              ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗    ║', 'cyan')}
{colored('║              ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝    ║', 'cyan')}
{colored('║              ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗  ║', 'cyan')}
{colored('║               ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝  ║', 'cyan')}
{colored('║                                                                               ║', 'cyan')}
{colored('║                   『 ULTIMATE CYBER WARFARE PLATFORM v2.0 』                   ║', 'yellow')}
{colored('║                                                                               ║', 'cyan')}
{colored('╚═══════════════════════════════════════════════════════════════════════════════╝', 'cyan')}

  {colored('Type "help" for commands | Type "exit" to quit', 'cyan')}
"""

print(banner)

# Demo commands
print(f"\n{colored('Demo Mode - Showing available commands:', 'yellow')}\n")

commands = {
    'Target Management': ['target', 'showtarget', 'cleartarget'],
    'Reconnaissance': ['quickscan', 'deepscan', 'servicescan', 'vulnscan', 'ping', 'traceroute'],
    'Network Analysis': ['dnsenum', 'subdomain', 'dnszone', 'whois', 'reverse'],
    'Web Testing': ['headerscan', 'sslscan', 'wafscan', 'cmsscan', 'robots'],
    'OSINT': ['emailharvest', 'social', 'metadata', 'techstack'],
    'Results': ['results', 'report', 'export', 'history']
}

for category, cmds in commands.items():
    print(f"{colored(category + ':', 'green')}")
    for cmd in cmds:
        print(f"  • {cmd}")
    print()

# Show example usage
print(f"\n{colored('Example Usage:', 'yellow')}\n")
print(f"{colored('cyber@guardian', 'cyan')} {colored('[no target]', 'yellow')} {colored('>', 'red')} target scanme.nmap.org")
print(f"{colored('✓', 'green')} Target set to: scanme.nmap.org\n")

print(f"{colored('cyber@guardian', 'cyan')} {colored('[scanme.nmap.org]', 'red')} {colored('>', 'red')} quickscan")
print(f"{colored('[►]', 'cyan')} Starting quick port scan...\n")

# Simulate scan
for i in range(5):
    print(f"  Scanning port range... {(i+1)*20}%")
    time.sleep(0.2)

print(f"\n{colored('Open Ports Found:', 'green')} 3\n")
print(f"  {colored('22', 'green'):<10} ssh                  OpenSSH 7.4")
print(f"  {colored('80', 'green'):<10} http                 Apache 2.4.6")
print(f"  {colored('443', 'green'):<10} https                Apache 2.4.6\n")

print(colored('═' * 70, 'green'))
print(f"  {colored('SUCCESS', 'green')} Quick scan completed!")
print(colored('═' * 70, 'green'))

print(f"\n{colored('cyber@guardian', 'cyan')} {colored('[scanme.nmap.org]', 'red')} {colored('>', 'red')} results")
print(f"\n{colored('╔═══════════════════════ SCAN RESULTS ═══════════════════════╗', 'green')}\n")
print(f"{colored('QUICKSCAN:', 'cyan')}")
print(f"  Found 3 items\n")
print(f"{colored('╚════════════════════════════════════════════════════════════╝', 'green')}\n")

print(f"{colored('💾 Tip:', 'cyan')} Use {colored('report', 'green')} to generate a full HTML report\n")

# Show auto-correction demo
print(f"\n{colored('Auto-Correction Demo:', 'yellow')}\n")
print(f"{colored('cyber@guardian', 'cyan')} {colored('[scanme.nmap.org]', 'red')} {colored('>', 'red')} quckscan")
print(f"\n{colored('Did you mean:', 'yellow')} {colored('quickscan', 'green')}?")
print(f"{colored('[y/n]:', 'cyan')} y")
print(f"{colored('✓', 'green')} Using: {colored('quickscan', 'green')}\n")

print(f"\n{colored('Installation Instructions:', 'yellow')}")
print(f"""
To use the full version with all tools, install dependencies:

  pip3 install -r requirements.txt

Or install individually:

  pip3 install termcolor requests beautifulsoup4 python-nmap pyyaml dnspython lxml

Then run:

  python3 main.py

{colored('⚠️  Note:', 'red')} Make sure nmap is installed on your system:

  sudo apt install nmap whois traceroute dnsutils

""")

print(f"{colored('Stay Safe. Stay Ethical. Happy Hacking! 👾🛡️', 'green')}\n")
