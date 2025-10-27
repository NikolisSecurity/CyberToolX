"""Network analysis and enumeration tools"""

import socket
import subprocess
import sys
import os
import dns.resolver
import dns.zone
import dns.query

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.color_compat import colored
from utils.ascii_art import AsciiArt


class NetworkTools:
    """Network analysis tools"""

    def __init__(self, target):
        self.target = target

    def dns_enum(self):
        """DNS enumeration"""
        print(f"\n{colored('Performing DNS enumeration...', 'cyan')}")
        print(AsciiArt.tool_category_banner('recon'))

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

        try:
            print(f"\n{colored('DNS Records for:', 'yellow')} {self.target}\n")

            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.target, record_type)
                    print(f"{colored(record_type, 'green')} Records:")
                    for rdata in answers:
                        print(f"  {rdata}")
                    print()
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    print(f"{colored('Domain does not exist', 'red')}")
                    return None
                except Exception:
                    pass

            AsciiArt.success_message("DNS enumeration completed")
            return True

        except Exception as e:
            AsciiArt.error_message(f"DNS enumeration failed: {str(e)}")
            return None


    def subdomain_enum(self):
        """Subdomain enumeration"""
        print(f"\n{colored('Subdomain Enumeration...', 'cyan')}")
        print(f"{colored('⚠ This may take a few minutes', 'yellow')}\n")

        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'forum', 'blog',
            'dev', 'staging', 'api', 'admin', 'portal', 'shop', 'store', 'cdn', 'test',
            'vpn', 'remote', 'gateway', 'backup', 'demo', 'app', 'support', 'helpdesk'
        ]

        found_subdomains = []

        try:
            for sub in common_subdomains:
                subdomain = f"{sub}.{self.target}"
                try:
                    ip = socket.gethostbyname(subdomain)
                    found_subdomains.append({'subdomain': subdomain, 'ip': ip})
                    print(f"{colored('✓', 'green')} {subdomain} → {ip}")
                except socket.gaierror:
                    pass

            if found_subdomains:
                print(f"\n{colored('Found Subdomains:', 'green', attrs=['bold'])} {len(found_subdomains)}")
                AsciiArt.success_message("Subdomain enumeration completed")
            else:
                AsciiArt.info_message("No subdomains found")

            return found_subdomains

        except Exception as e:
            AsciiArt.error_message(f"Subdomain enumeration failed: {str(e)}")
            return []

    def zone_transfer(self):
        """Attempt DNS zone transfer"""
        print(f"\n{colored('Attempting DNS zone transfer...', 'cyan')}")

        try:
            # Get nameservers
            ns_records = dns.resolver.resolve(self.target, 'NS')

            for ns in ns_records:
                ns_name = str(ns.target).rstrip('.')
                print(f"\n{colored('Trying nameserver:', 'yellow')} {ns_name}")

                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_name, self.target, timeout=10))
                    print(f"{colored('✓ ZONE TRANSFER SUCCESSFUL!', 'red', attrs=['bold'])}")
                    print(f"{colored('⚠ This is a security vulnerability!', 'red')}\n")

                    for name, node in zone.nodes.items():
                        print(f"{name} {node.to_text(name)}")

                    AsciiArt.error_message("Zone transfer vulnerability found!")
                    return True

                except Exception:
                    print(f"{colored('✗', 'green')} Transfer denied (good)")

            AsciiArt.success_message("No zone transfer vulnerability")
            return False

        except Exception as e:
            AsciiArt.error_message(f"Zone transfer check failed: {str(e)}")
            return None
