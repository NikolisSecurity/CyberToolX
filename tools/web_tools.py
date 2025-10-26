"""Web application security testing tools"""

import requests
import ssl
import socket
import sys
import os
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.color_compat import colored
from utils.ascii_art import AsciiArt

# Optional OpenSSL import for advanced SSL features
try:
    from OpenSSL import crypto
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False


class WebTools:
    """Web application testing tools"""

    def __init__(self, target):
        self.target = target if target.startswith('http') else f'http://{target}'
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CyberGuardian/2.0'})

    def headers_scan(self):
        """Analyze security headers"""
        print(f"\n{colored('Analyzing security headers...', 'cyan')}")
        print(AsciiArt.tool_category_banner('web'))

        security_headers = {
            'Strict-Transport-Security': {'present': False, 'severity': 'high'},
            'Content-Security-Policy': {'present': False, 'severity': 'high'},
            'X-Frame-Options': {'present': False, 'severity': 'medium'},
            'X-Content-Type-Options': {'present': False, 'severity': 'medium'},
            'X-XSS-Protection': {'present': False, 'severity': 'low'},
            'Referrer-Policy': {'present': False, 'severity': 'low'},
            'Permissions-Policy': {'present': False, 'severity': 'low'}
        }

        try:
            response = requests.get(self.target, timeout=10, verify=False)

            print(f"\n{colored('Target:', 'yellow')} {self.target}")
            print(f"{colored('Status:', 'yellow')} {response.status_code}\n")

            # Check security headers
            for header, info in security_headers.items():
                if header in response.headers:
                    info['present'] = True
                    info['value'] = response.headers[header]
                    print(f"{colored('✓', 'green')} {colored(header, 'green')}: {response.headers[header][:60]}")
                else:
                    severity_color = {'high': 'red', 'medium': 'yellow', 'low': 'white'}
                    print(f"{colored('✗', 'red')} {colored(header, severity_color[info['severity']])} - MISSING ({info['severity']} risk)")

            # Additional interesting headers
            print(f"\n{colored('Server Information:', 'cyan')}")
            print(f"  Server: {response.headers.get('Server', 'Not disclosed')}")
            print(f"  Powered-By: {response.headers.get('X-Powered-By', 'Not disclosed')}")

            missing_critical = sum(1 for h in security_headers.values() if not h['present'] and h['severity'] == 'high')

            if missing_critical > 0:
                AsciiArt.warning_message(f"{missing_critical} critical security headers missing!")
            else:
                AsciiArt.success_message("Security headers look good!")

            return security_headers

        except Exception as e:
            AsciiArt.error_message(f"Header scan failed: {str(e)}")
            return None

    def ssl_scan(self):
        """Analyze SSL/TLS configuration"""
        print(f"\n{colored('Analyzing SSL/TLS configuration...', 'cyan')}")
        print(AsciiArt.tool_category_banner('web'))

        parsed = urlparse(self.target)
        hostname = parsed.hostname or self.target
        port = parsed.port or 443

        try:
            # Get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_dict = ssock.getpeercert()
                    protocol = ssock.version()

                    if cert_dict:
                        print(f"\n{colored('Certificate Information:', 'green', attrs=['bold'])}")
                        print(f"  Subject: {dict(x[0] for x in cert_dict.get('subject', [])).get('commonName', 'N/A')}")
                        print(f"  Issuer: {dict(x[0] for x in cert_dict.get('issuer', [])).get('commonName', 'N/A')}")
                        print(f"  Valid From: {cert_dict.get('notBefore', 'N/A')}")
                        print(f"  Valid Until: {cert_dict.get('notAfter', 'N/A')}")
                        print(f"  Version: {cert_dict.get('version', 'N/A')}")
                        print(f"  Serial: {cert_dict.get('serialNumber', 'N/A')}")

                        # Basic expiry check (simplified without OpenSSL)
                        AsciiArt.success_message("Certificate retrieved successfully")

                    # Protocol version
                    print(f"\n{colored('Protocol:', 'yellow')} {protocol}")

                    if protocol in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        AsciiArt.warning_message(f"Weak protocol detected: {protocol}")
                    else:
                        print(f"{colored('✓', 'green')} Strong protocol in use")

                    # Advanced analysis if OpenSSL is available
                    if HAS_OPENSSL:
                        cert_bin = ssock.getpeercert(binary_form=True)
                        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)

                        if cert.has_expired():
                            AsciiArt.error_message("⚠ Certificate has EXPIRED!")
                        else:
                            print(f"{colored('✓', 'green')} Certificate is valid and not expired")

                    return {
                        'cert': cert_dict,
                        'protocol': protocol
                    }

        except Exception as e:
            AsciiArt.error_message(f"SSL scan failed: {str(e)}")
            return None

    def robots_check(self):
        """Check robots.txt and sitemap"""
        print(f"\n{colored('Checking robots.txt and sitemap...', 'cyan')}")

        robots_url = f"{self.target.rstrip('/')}/robots.txt"
        sitemap_url = f"{self.target.rstrip('/')}/sitemap.xml"

        print(f"\n{colored('robots.txt:', 'yellow')}")
        try:
            response = requests.get(robots_url, timeout=5)
            if response.status_code == 200:
                print(response.text[:1000])
                AsciiArt.success_message("robots.txt found")
            else:
                print(f"{colored('Not found', 'yellow')}")
        except Exception as e:
            print(f"{colored('Error:', 'red')} {str(e)}")

        print(f"\n{colored('sitemap.xml:', 'yellow')}")
        try:
            response = requests.get(sitemap_url, timeout=5)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'xml')
                urls = soup.find_all('loc')
                print(f"Found {len(urls)} URLs in sitemap")
                for url in urls[:10]:
                    print(f"  {url.text}")
                if len(urls) > 10:
                    print(f"  ... and {len(urls) - 10} more")
                AsciiArt.success_message("sitemap.xml found")
            else:
                print(f"{colored('Not found', 'yellow')}")
        except Exception as e:
            print(f"{colored('Error:', 'red')} {str(e)}")

    def waf_detect(self):
        """Detect Web Application Firewall"""
        print(f"\n{colored('Detecting WAF/CDN...', 'cyan')}")
        print(AsciiArt.tool_category_banner('web'))

        waf_signatures = {
            'cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
            'akamai': ['akamai', 'ak_bmsc'],
            'aws': ['x-amz', 'awselb'],
            'imperva': ['incap_ses', 'visid_incap'],
            'f5': ['BigIP', 'F5', 'TS'],
            'sucuri': ['x-sucuri'],
            'wordfence': ['wordfence']
        }

        try:
            # Normal request
            response = requests.get(self.target, timeout=10)

            # Check headers and cookies
            detected_wafs = []

            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if any(sig.lower() in h.lower() for h in response.headers.keys()):
                        detected_wafs.append(waf_name)
                        break
                    if any(sig.lower() in c.lower() for c in response.cookies.keys()):
                        detected_wafs.append(waf_name)
                        break

            if detected_wafs:
                print(f"\n{colored('⚠ WAF/CDN Detected:', 'red', attrs=['bold'])}")
                for waf in set(detected_wafs):
                    print(f"  • {colored(waf.upper(), 'red')}")
                AsciiArt.warning_message("WAF protection active - aggressive scans may be blocked")
            else:
                AsciiArt.success_message("No WAF detected (or well hidden)")

            return detected_wafs

        except Exception as e:
            AsciiArt.error_message(f"WAF detection failed: {str(e)}")
            return []

    def cms_detect(self):
        """Detect CMS and version"""
        print(f"\n{colored('Detecting CMS...', 'cyan')}")

        cms_signatures = {
            'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
            'Joomla': ['/administrator/', 'com_content', 'Joomla!'],
            'Drupal': ['/sites/default/', 'Drupal', '/node/'],
            'Magento': ['/skin/frontend/', 'Magento', '/mage/'],
            'Shopify': ['cdn.shopify.com', 'Shopify'],
            'Wix': ['wix.com', 'Wix'],
            'Squarespace': ['squarespace.com', 'Squarespace']
        }

        try:
            response = requests.get(self.target, timeout=10)
            html = response.text

            detected = []
            for cms, signatures in cms_signatures.items():
                if any(sig in html for sig in signatures):
                    detected.append(cms)

            if detected:
                print(f"\n{colored('CMS Detected:', 'green', attrs=['bold'])}")
                for cms in detected:
                    print(f"  • {colored(cms, 'green')}")
                AsciiArt.success_message("CMS identification complete")
            else:
                AsciiArt.info_message("No common CMS detected")

            return detected

        except Exception as e:
            AsciiArt.error_message(f"CMS detection failed: {str(e)}")
            return []
