"""Interactive menu system for CyberGuardian Ultimate"""

import os
import sys
from termcolor import colored
from .ascii_art import AsciiArt
from .command_parser import CommandParser


class MenuSystem:
    """Interactive menu-driven interface"""

    def __init__(self):
        self.running = True
        self.current_target = None
        self.scan_results = {}

        # Define all available commands
        self.commands = {
            # Main Menu
            'help': 'Display available commands and usage',
            'clear': 'Clear the screen',
            'exit': 'Exit CyberGuardian Ultimate',
            'quit': 'Exit CyberGuardian Ultimate',
            'banner': 'Display the main banner',
            'about': 'About CyberGuardian Ultimate',

            # Target Management
            'target': 'Set target for scanning (usage: target <ip/domain>)',
            'showtarget': 'Display current target',
            'cleartarget': 'Clear current target',

            # Reconnaissance Tools
            'portscan': 'Comprehensive port scanning',
            'quickscan': 'Quick scan of common ports',
            'deepscan': 'Deep scan of all 65535 ports',
            'servicescan': 'Service version detection',
            'vulnscan': 'Vulnerability scanning',
            'nmap': 'Advanced nmap scanning with custom options',

            # Network Analysis
            'ping': 'ICMP ping test',
            'traceroute': 'Trace route to target',
            'dnsenum': 'DNS enumeration',
            'dnszone': 'DNS zone transfer attempt',
            'subdomain': 'Subdomain enumeration',
            'whois': 'WHOIS lookup',
            'geoip': 'Geolocation lookup',
            'reverse': 'Reverse DNS lookup',
            'portsweep': 'Sweep multiple hosts for open ports',

            # Web Application Testing
            'webscan': 'Complete web application scan',
            'dirscan': 'Directory and file enumeration',
            'sqlmap': 'SQL injection testing',
            'xsstest': 'XSS vulnerability testing',
            'csrftest': 'CSRF vulnerability testing',
            'headerscan': 'Security headers analysis',
            'sslscan': 'SSL/TLS configuration scan',
            'wafscan': 'WAF detection and fingerprinting',
            'cmsscan': 'CMS detection and version check',
            'apiscan': 'API endpoint discovery',
            'graphql': 'GraphQL introspection',
            'jwtscan': 'JWT token analysis',
            'robots': 'Check robots.txt and sitemap.xml',

            # Exploitation
            'exploitsearch': 'Search for exploits',
            'metasploit': 'Metasploit integration',
            'shellgen': 'Reverse shell generator',
            'payloadgen': 'Payload generator',
            'exploit': 'Execute exploit module',

            # Wireless Security
            'wifiscan': 'Scan for wireless networks',
            'wificrack': 'Wireless password cracking',
            'bluetooth': 'Bluetooth device scanning',
            'rogue': 'Rogue AP detection',

            # Password & Hash Tools
            'hashcrack': 'Crack password hashes',
            'hashid': 'Identify hash type',
            'passgen': 'Generate password wordlist',
            'bruteforce': 'Brute force attack',
            'hydra': 'Network service bruteforce (Hydra)',

            # Forensics & OSINT
            'emailharvest': 'Email address harvesting',
            'metadata': 'Extract file metadata',
            'social': 'Social media OSINT',
            'phonelookup': 'Phone number lookup',
            'iplookup': 'IP address intelligence',
            'breach': 'Check if email/password in breach',
            'peoplesearch': 'People search OSINT',

            # Reporting & Results
            'results': 'Show scan results',
            'report': 'Generate comprehensive report',
            'export': 'Export results to file',
            'history': 'View scan history',
            'compare': 'Compare multiple scan results',

            # Configuration
            'settings': 'View/modify settings',
            'proxy': 'Configure proxy settings',
            'threads': 'Set thread count',
            'timeout': 'Set connection timeout',
            'verbose': 'Toggle verbose output',
            'update': 'Update tool databases',

            # Advanced
            'script': 'Run automation script',
            'schedule': 'Schedule recurring scans',
            'monitor': 'Continuous monitoring mode',
            'honeypot': 'Deploy honeypot',
            'custom': 'Execute custom command'
        }

        self.parser = CommandParser(self.commands)

    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name != 'nt' else 'cls')

    def display_prompt(self):
        """Display beautiful command prompt"""
        if self.current_target:
            target_display = colored(f'[{self.current_target}]', 'red', attrs=['bold'])
        else:
            target_display = colored('[no target]', 'yellow')

        prompt = f"{colored('cyber', 'cyan', attrs=['bold'])}{colored('@', 'white')}"\
                 f"{colored('guardian', 'green', attrs=['bold'])} "\
                 f"{target_display} {colored('>', 'red', attrs=['bold'])} "
        return prompt

    def display_help(self, category=None):
        """Display help information"""
        self.clear_screen()
        print(colored("\n╔═══════════════════════ COMMAND REFERENCE ═══════════════════════╗\n", 'cyan', attrs=['bold']))

        categories = {
            'Main': ['help', 'clear', 'exit', 'quit', 'banner', 'about'],
            'Target Management': ['target', 'showtarget', 'cleartarget'],
            'Reconnaissance': ['portscan', 'quickscan', 'deepscan', 'servicescan', 'vulnscan', 'nmap'],
            'Network Analysis': ['ping', 'traceroute', 'dnsenum', 'dnszone', 'subdomain', 'whois', 'geoip', 'reverse', 'portsweep'],
            'Web Testing': ['webscan', 'dirscan', 'sqlmap', 'xsstest', 'csrftest', 'headerscan', 'sslscan', 'wafscan', 'cmsscan', 'apiscan', 'graphql', 'jwtscan', 'robots'],
            'Exploitation': ['exploitsearch', 'metasploit', 'shellgen', 'payloadgen', 'exploit'],
            'Wireless': ['wifiscan', 'wificrack', 'bluetooth', 'rogue'],
            'Password Tools': ['hashcrack', 'hashid', 'passgen', 'bruteforce', 'hydra'],
            'Forensics & OSINT': ['emailharvest', 'metadata', 'social', 'phonelookup', 'iplookup', 'breach', 'peoplesearch'],
            'Reporting': ['results', 'report', 'export', 'history', 'compare'],
            'Configuration': ['settings', 'proxy', 'threads', 'timeout', 'verbose', 'update'],
            'Advanced': ['script', 'schedule', 'monitor', 'honeypot', 'custom']
        }

        for cat_name, cmd_list in categories.items():
            print(colored(f"  {cat_name}:", 'yellow', attrs=['bold']))
            for cmd in cmd_list:
                desc = self.commands.get(cmd, 'No description')
                print(f"    {colored(cmd, 'green'):<20} - {colored(desc, 'white')}")
            print()

        print(colored("╚════════════════════════════════════════════════════════════════╝\n", 'cyan', attrs=['bold']))

    def display_about(self):
        """Display about information"""
        self.clear_screen()
        about_text = f"""
{colored('╔════════════════════════════════════════════════════════════════╗', 'cyan')}
{colored('║', 'cyan')}                    ABOUT CYBERGUARDIAN ULTIMATE                {colored('║', 'cyan')}
{colored('╚════════════════════════════════════════════════════════════════╝', 'cyan')}

{colored('Version:', 'yellow')} 2.0 Ultimate Edition
{colored('Codename:', 'yellow')} "Ghost Protocol"

{colored('Description:', 'yellow')}
  CyberGuardian Ultimate is a comprehensive cybersecurity platform
  combining offensive and defensive security tools into one powerful
  command-line interface. Designed for penetration testers, security
  researchers, and red/blue team operators.

{colored('Features:', 'yellow')}
  • 60+ Built-in Security Tools
  • Interactive Menu System with Auto-Correction
  • Multi-Target Campaign Management
  • Automated Vulnerability Scanning
  • Advanced Web Application Testing
  • Wireless Security Assessment
  • Password & Hash Cracking
  • Digital Forensics & OSINT
  • Comprehensive Reporting
  • Scriptable & Schedulable Scans

{colored('Legal Notice:', 'red', attrs=['bold'])}
  This tool is for AUTHORIZED TESTING ONLY. Unauthorized access to
  computer systems is illegal. Always obtain written permission before
  testing any systems you do not own.

{colored('Author:', 'yellow')} CyberGuardian Team
{colored('License:', 'yellow')} For authorized security professionals only
{colored('Website:', 'yellow')} https://github.com/NikolisSecurity/CyberToolX

{colored('Press Enter to continue...', 'cyan')}
        """
        print(about_text)
        input()

    def run(self):
        """Main menu loop"""
        # Show loading screen
        self.clear_screen()
        AsciiArt.loading_screen()
        self.clear_screen()

        # Show main banner
        print(AsciiArt.main_banner())
        print(colored("  Type 'help' for available commands | Type 'exit' to quit\n", 'cyan'))

        while self.running:
            try:
                user_input = input(self.display_prompt())

                if not user_input.strip():
                    continue

                command, args = self.parser.parse(user_input)

                if command is None:
                    continue

                # Execute command
                self.execute_command(command, args)

            except KeyboardInterrupt:
                print(f"\n\n{colored('Use', 'yellow')} {colored('exit', 'green', attrs=['bold'])} {colored('to quit', 'yellow')}\n")
                continue
            except EOFError:
                break
            except Exception as e:
                print(f"\n{colored('✗ Error:', 'red', attrs=['bold'])} {str(e)}\n")

    def execute_command(self, command, args):
        """Execute a parsed command"""
        # Main commands
        if command == 'help':
            self.display_help()
        elif command == 'clear':
            self.clear_screen()
            print(AsciiArt.main_banner())
        elif command in ['exit', 'quit']:
            self.running = False
            print(f"\n{colored('Shutting down CyberGuardian Ultimate...', 'cyan')}")
            print(colored('Stay safe. Stay ethical. 👾\n', 'green'))
        elif command == 'banner':
            self.clear_screen()
            print(AsciiArt.main_banner())
        elif command == 'about':
            self.display_about()

        # Target management
        elif command == 'target':
            if args:
                self.current_target = args[0]
                AsciiArt.success_message(f"Target set to: {self.current_target}")
            else:
                AsciiArt.error_message("Usage: target <ip/domain>")
        elif command == 'showtarget':
            if self.current_target:
                print(f"\n{colored('Current target:', 'cyan')} {colored(self.current_target, 'green', attrs=['bold'])}\n")
            else:
                AsciiArt.warning_message("No target set. Use 'target <ip/domain>' to set one.")
        elif command == 'cleartarget':
            self.current_target = None
            AsciiArt.success_message("Target cleared")

        # Tool execution - placeholder for now
        else:
            self.execute_tool(command, args)

    def execute_tool(self, tool, args):
        """Execute a security tool"""
        if not self.current_target and tool not in ['hashid', 'hashcrack', 'passgen', 'settings', 'update']:
            AsciiArt.error_message("No target set. Use 'target <ip/domain>' first.")
            return

        print(f"\n{colored('⚡', 'yellow')} Executing: {colored(tool, 'green', attrs=['bold'])}")
        print(f"{colored('Target:', 'cyan')} {colored(self.current_target or 'N/A', 'white')}")
        print(f"{colored('Status:', 'cyan')} {colored('Tool integration in progress...', 'yellow')}\n")

        # Placeholder - actual tool implementations will be added
        AsciiArt.info_message(f"Tool '{tool}' is being integrated. Check back soon!")
