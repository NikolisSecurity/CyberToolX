"""Reconnaissance and scanning tools"""

import nmap
import socket
import subprocess
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.color_compat import colored
from utils.ascii_art import AsciiArt


class ReconTools:
    """Reconnaissance and enumeration tools"""

    def __init__(self, target):
        self.target = target
        self.nm = nmap.PortScanner()

    def quick_scan(self):
        """Quick scan of top 100 common ports"""
        print(f"\n{colored('Starting quick port scan...', 'cyan')}")
        print(AsciiArt.tool_category_banner('recon'))

        try:
            # Scan top 100 ports
            self.nm.scan(self.target, arguments='-F --open -T4')

            if self.target in self.nm.all_hosts():
                host = self.nm[self.target]
                print(f"\n{colored('Target:', 'yellow')} {self.target}")
                print(f"{colored('State:', 'yellow')} {host.state()}")

                open_ports = []
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        service = host[proto][port]
                        if service['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'service': service['name'],
                                'version': service.get('product', '') + ' ' + service.get('version', '')
                            })

                if open_ports:
                    print(f"\n{colored('Open Ports Found:', 'green', attrs=['bold'])} {len(open_ports)}\n")
                    print(f"{colored('PORT', 'cyan'):<10} {colored('SERVICE', 'cyan'):<20} {colored('VERSION', 'cyan')}")
                    print("─" * 70)
                    for p in open_ports:
                        print(f"{colored(str(p['port']), 'green'):<10} {p['service']:<20} {p['version']}")

                    AsciiArt.success_message("Quick scan completed!")
                    return open_ports
                else:
                    AsciiArt.warning_message("No open ports found")
                    return []
            else:
                AsciiArt.error_message("Target unreachable or no open ports")
                return []

        except Exception as e:
            AsciiArt.error_message(f"Scan failed: {str(e)}")
            return []

    def deep_scan(self):
        """Deep scan of all 65535 ports"""
        print(f"\n{colored('Starting deep port scan (all 65535 ports)...', 'cyan')}")
        print(f"{colored('⚠ This may take 10-30 minutes', 'yellow')}")
        print(AsciiArt.tool_category_banner('recon'))

        try:
            self.nm.scan(self.target, '1-65535', arguments='--open -T4')

            if self.target in self.nm.all_hosts():
                host = self.nm[self.target]
                open_ports = []

                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        service = host[proto][port]
                        if service['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'service': service['name'],
                                'version': service.get('product', '') + ' ' + service.get('version', '')
                            })

                print(f"\n{colored('Total Open Ports:', 'green', attrs=['bold'])} {len(open_ports)}\n")
                for p in open_ports:
                    print(f"  {colored(str(p['port']), 'green'):<10} {p['service']:<20} {p['version']}")

                AsciiArt.success_message("Deep scan completed!")
                return open_ports
            else:
                AsciiArt.error_message("Target unreachable")
                return []

        except Exception as e:
            AsciiArt.error_message(f"Scan failed: {str(e)}")
            return []

    def service_scan(self):
        """Aggressive service version detection"""
        print(f"\n{colored('Starting service version detection...', 'cyan')}")
        print(AsciiArt.tool_category_banner('recon'))

        try:
            self.nm.scan(self.target, arguments='-sV -sC --version-all -T4')

            if self.target in self.nm.all_hosts():
                host = self.nm[self.target]
                services = []

                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        service = host[proto][port]
                        services.append({
                            'port': port,
                            'name': service['name'],
                            'product': service.get('product', 'unknown'),
                            'version': service.get('version', 'unknown'),
                            'extrainfo': service.get('extrainfo', ''),
                            'cpe': service.get('cpe', '')
                        })

                print(f"\n{colored('Services Detected:', 'green', attrs=['bold'])} {len(services)}\n")
                for s in services:
                    print(f"{colored('Port:', 'cyan')} {s['port']}")
                    print(f"  Service: {s['name']}")
                    print(f"  Product: {s['product']} {s['version']}")
                    if s['extrainfo']:
                        print(f"  Info: {s['extrainfo']}")
                    if s['cpe']:
                        print(f"  CPE: {s['cpe']}")
                    print()

                AsciiArt.success_message("Service detection completed!")
                return services
            else:
                AsciiArt.error_message("Target unreachable")
                return []

        except Exception as e:
            AsciiArt.error_message(f"Service scan failed: {str(e)}")
            return []

    def vuln_scan(self):
        """Vulnerability scanning with NSE scripts"""
        print(f"\n{colored('Starting vulnerability scan...', 'cyan')}")
        print(AsciiArt.tool_category_banner('recon'))

        try:
            # Use vulnerability detection scripts
            self.nm.scan(self.target, arguments='--script vuln -sV')

            if self.target in self.nm.all_hosts():
                host = self.nm[self.target]
                vulns = []

                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        service = host[proto][port]
                        if 'script' in service:
                            for script_name, script_output in service['script'].items():
                                if 'VULNERABLE' in script_output.upper() or 'CVE' in script_output.upper():
                                    vulns.append({
                                        'port': port,
                                        'service': service['name'],
                                        'script': script_name,
                                        'output': script_output
                                    })

                if vulns:
                    print(f"\n{colored('⚠ VULNERABILITIES FOUND:', 'red', attrs=['bold'])} {len(vulns)}\n")
                    for v in vulns:
                        print(colored('═' * 70, 'red'))
                        print(f"{colored('Port:', 'yellow')} {v['port']} ({v['service']})")
                        print(f"{colored('Detection:', 'yellow')} {v['script']}")
                        print(f"{colored('Details:', 'yellow')}")
                        print(v['output'][:500])  # Limit output
                        print()

                    AsciiArt.error_message(f"Found {len(vulns)} potential vulnerabilities!")
                    return vulns
                else:
                    AsciiArt.success_message("No obvious vulnerabilities detected")
                    return []
            else:
                AsciiArt.error_message("Target unreachable")
                return []

        except Exception as e:
            AsciiArt.error_message(f"Vulnerability scan failed: {str(e)}")
            return []

    def ping_test(self):
        """ICMP ping test"""
        print(f"\n{colored('Running ICMP ping test...', 'cyan')}")

        try:
            # Try to ping
            result = subprocess.run(['ping', '-c', '4', self.target],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                print(result.stdout)
                AsciiArt.success_message("Target is reachable")
                return True
            else:
                AsciiArt.warning_message("Target did not respond to ping")
                return False

        except subprocess.TimeoutExpired:
            AsciiArt.error_message("Ping timeout")
            return False
        except Exception as e:
            AsciiArt.error_message(f"Ping failed: {str(e)}")
            return False

    def traceroute(self):
        """Trace route to target"""
        print(f"\n{colored('Tracing route to target...', 'cyan')}")

        try:
            result = subprocess.run(['traceroute', self.target],
                                  capture_output=True, text=True, timeout=60)
            print(result.stdout)
            AsciiArt.success_message("Traceroute completed")
            return result.stdout

        except subprocess.TimeoutExpired:
            AsciiArt.error_message("Traceroute timeout")
            return None
        except FileNotFoundError:
            AsciiArt.error_message("Traceroute command not found. Install with: sudo apt install traceroute")
            return None
        except Exception as e:
            AsciiArt.error_message(f"Traceroute failed: {str(e)}")
            return None
