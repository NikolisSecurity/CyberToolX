"""Web application security testing tools

Enhanced with advanced penetration testing modules for comprehensive
web application security assessment.
"""

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

# Import advanced testing modules
try:
    from tools.advanced_sql_injection import AdvancedSQLInjection
    from tools.nosql_injection import NoSQLInjection
    from tools.command_injection import CommandInjection
    from tools.advanced_xss import AdvancedXSS
    from tools.advanced_csrf import AdvancedCSRF
    from tools.ssrf_testing import SSRFTesting
    from tools.xxe_testing import XXETesting
    from tools.api_enumerator import APIEnumerator
    HAS_ADVANCED_MODULES = True
except ImportError:
    HAS_ADVANCED_MODULES = False

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

    def webscan(self):
        """Complete web application scan - runs multiple tests"""
        print(colored("\n╔═══════════════════ COMPREHENSIVE WEB SCAN ══════════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        results = {
            'target': self.target,
            'headers': None,
            'ssl': None,
            'waf': None,
            'cms': None,
            'vulnerabilities': []
        }

        # Run scans in sequence
        print(f"{colored('Running security tests...', 'yellow')}\n")

        try:
            results['headers'] = self.headers_scan()
            print(f"{colored('✓', 'green')} Security Headers Analysis complete\n")
        except: pass

        try:
            results['ssl'] = self.ssl_scan()
            print(f"{colored('✓', 'green')} SSL/TLS Configuration complete\n")
        except: pass

        try:
            self.robots_check()
            print(f"{colored('✓', 'green')} robots.txt/sitemap.xml complete\n")
        except: pass

        try:
            results['waf'] = self.waf_detect()
            print(f"{colored('✓', 'green')} WAF Detection complete\n")
        except: pass

        try:
            results['cms'] = self.cms_detect()
            print(f"{colored('✓', 'green')} CMS Detection complete\n")
        except: pass

        # Quick vulnerability check
        try:
            print(f"{colored('Vulnerability Quick Check...', 'yellow')}")
            response = requests.get(self.target, timeout=10, verify=False)

            # Check for open redirect
            if 'url=' in self.target or 'redirect=' in self.target or 'next=' in self.target:
                results['vulnerabilities'].append({'type': 'Open Redirect', 'severity': 'MEDIUM'})

            # Check CORS misconfiguration
            cors_headers = response.headers.get('Access-Control-Allow-Origin')
            if cors_headers and ('*' in cors_headers or 'null' in cors_headers):
                results['vulnerabilities'].append({'type': 'CORS Misconfiguration', 'severity': 'MEDIUM'})

            print(f"{colored('✓', 'green')} Vulnerability Quick Check complete\n")
        except: pass

        # Summary
        print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))
        print(f"{colored('SCAN COMPLETE', 'green', attrs=['bold'])}\n")
        print(f"{colored('Summary:', 'yellow')}")
        print(f"  • Security Headers: {colored('Analyzed', 'green') if results['headers'] else colored('N/A', 'white')}")
        print(f"  • SSL/TLS: {colored('Analyzed', 'green') if results['ssl'] else colored('N/A', 'white')}")
        print(f"  • WAF: {colored('Detected', 'yellow') if results['waf'] else colored('None detected', 'green')}")
        print(f"  • CMS: {colored('Detected', 'green') if results['cms'] else colored('Not detected', 'white')}")
        print(f"  • Vulnerabilities Found: {colored(str(len(results['vulnerabilities'])), 'red' if results['vulnerabilities'] else 'green')}\n")

        return results

    def dirscan(self):
        """Directory and file enumeration"""
        print(colored("\n╔═══════════════════ DIRECTORY ENUMERATION ════════════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}")

        # Use existing directory_enum from scanner
        try:
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from core.scanner import CyberSentinel

            scanner = CyberSentinel()
            print(f"{colored('Wordlist:', 'yellow')} common.txt")
            print(f"{colored('Threads:', 'yellow')} 50\n")

            print(f"{colored('Scanning directories...', 'yellow')}\n")

            # Run directory enumeration
            scanner.directory_enum(self.target)

            # Display results
            found = scanner.findings['directories']
            if found:
                print(f"\n{colored('FOUND DIRECTORIES & FILES:', 'green', attrs=['bold'])}")
                for item in found[:20]:  # Show first 20
                    status = item['status']
                    if status == 200:
                        color = 'green'
                    elif status in [301, 302]:
                        color = 'yellow'
                    elif status in [401, 403]:
                        color = 'red'
                    else:
                        color = 'white'
                    print(f"[{colored(status, color)}] {item['url']}")

                if len(found) > 20:
                    print(f"\n... and {len(found) - 20} more\n")

            print(colored("\n╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))
            print(f"{colored('Summary:', 'yellow')} Found {colored(str(len(found)), 'green')} paths\n")

            return found

        except Exception as e:
            AsciiArt.error_message(f"Directory scan failed: {str(e)}")
            return []

    def sqlmap_scan(self):
        """SQL injection testing"""
        print(colored("\n╔═══════════════════ SQL INJECTION TESTING ════════════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        from urllib.parse import urlparse, parse_qs

        try:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)

            if not params:
                AsciiArt.info_message("No URL parameters found to test")
                return {}

            print(f"{colored('Testing parameters for SQL injection...', 'yellow')}\n")

            results = {}
            payloads = ["'", '"', "' OR '1'='1", '" OR "1"="1', "1' ORDER BY 1--"]
            sql_errors = ['SQL syntax', 'mysql_fetch', 'PostgreSQL', 'ORA-', 'ODBC', 'sqlite', 'syntax error']

            for param_name in params.keys():
                print(f"{colored('Testing parameter:', 'yellow')} {colored(param_name, 'white')}")
                vulnerable = False
                vuln_type = None
                vuln_payload = None

                for payload in payloads:
                    try:
                        # Build test URL
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_query = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

                        response = requests.get(test_url, timeout=5, verify=False)

                        # Check for SQL error messages
                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                vulnerable = True
                                vuln_type = 'ERROR-BASED'
                                vuln_payload = payload
                                print(f"  {colored('✗ VULNERABLE', 'red', attrs=['bold'])} - Error-based SQL injection")
                                print(f"  Payload: {colored(payload, 'yellow')}")
                                print(f"  Severity: {colored('HIGH', 'red', attrs=['bold'])}\n")
                                break

                        if vulnerable:
                            break

                    except Exception:
                        continue

                if not vulnerable:
                    print(f"  {colored('✓ SAFE', 'green')} - No injection detected\n")

                results[param_name] = {
                    'vulnerable': vulnerable,
                    'type': vuln_type,
                    'payload': vuln_payload
                }

            print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))

            vuln_count = sum(1 for r in results.values() if r['vulnerable'])
            if vuln_count > 0:
                print(f"{colored('⚠ VULNERABLE PARAMETERS:', 'red', attrs=['bold'])} {vuln_count}/{len(results)}")
                print(f"{colored('⚠ Warning:', 'yellow')} Manual verification recommended\n")
            else:
                print(f"{colored('✓ All parameters appear safe', 'green')}\n")

            return results

        except Exception as e:
            AsciiArt.error_message(f"SQL injection test failed: {str(e)}")
            return {}

    def xss_test(self):
        """Cross-Site Scripting vulnerability testing"""
        print(colored("\n╔═══════════════════ XSS VULNERABILITY TESTING ════════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        from urllib.parse import urlparse, parse_qs

        try:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)

            if not params:
                AsciiArt.info_message("No URL parameters found to test")
                return {}

            print(f"{colored('Testing for reflected XSS...', 'yellow')}\n")

            results = {}
            payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '"><svg onload=alert(1)>']

            for param_name in params.keys():
                print(f"{colored('Testing parameter:', 'yellow')} {colored(param_name, 'white')}")
                vulnerable = False
                vuln_payload = None

                for payload in payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_query = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

                        response = requests.get(test_url, timeout=5, verify=False)

                        # Check if payload appears unencoded in response
                        if payload in response.text:
                            vulnerable = True
                            vuln_payload = payload
                            print(f"  {colored('✗ VULNERABLE', 'red', attrs=['bold'])} - Reflected XSS")
                            print(f"  Payload: {colored(payload, 'yellow')}")
                            print(f"  Context: {colored('HTML body (unfiltered)', 'red')}")
                            print(f"  Severity: {colored('HIGH', 'red', attrs=['bold'])}\n")
                            break

                    except Exception:
                        continue

                if not vulnerable:
                    print(f"  {colored('✓ SAFE', 'green')} - No XSS detected\n")

                results[param_name] = {
                    'vulnerable': vulnerable,
                    'payload': vuln_payload,
                    'filtered': not vulnerable
                }

            print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))

            vuln_count = sum(1 for r in results.values() if r['vulnerable'])
            if vuln_count > 0:
                print(f"{colored('⚠ VULNERABLE PARAMETERS:', 'red', attrs=['bold'])} {vuln_count}/{len(results)}")
                print(f"{colored('⚠ Warning:', 'yellow')} Always test in safe environment\n")
            else:
                print(f"{colored('✓ All parameters appear safe', 'green')}\n")

            return results

        except Exception as e:
            AsciiArt.error_message(f"XSS test failed: {str(e)}")
            return {}

    def csrf_test(self):
        """CSRF vulnerability testing"""
        print(colored("\n╔═══════════════════ CSRF VULNERABILITY TESTING ═══════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        try:
            print(f"{colored('Analyzing CSRF protections...', 'yellow')}\n")

            response = requests.get(self.target, timeout=10, verify=False)
            html = response.text.lower()

            # Check for CSRF tokens in forms
            csrf_token_found = False
            token_names = ['csrf', 'token', '_token', 'authenticity_token', 'csrfmiddlewaretoken']
            for token_name in token_names:
                if f'name="{token_name}"' in html or f"name='{token_name}'" in html:
                    csrf_token_found = True
                    break

            # Check cookies for SameSite attribute
            samesite_cookies = False
            for cookie in response.cookies:
                if hasattr(cookie, 'get') and cookie.get('samesite'):
                    samesite_cookies = True
                    break

            # Check if forms use POST (good practice)
            post_forms = '<form' in html and 'method="post"' in html or "method='post'" in html

            # Display findings
            if csrf_token_found:
                print(f"{colored('✓', 'green')} CSRF token found in forms")
            else:
                print(f"{colored('✗', 'red')} No CSRF token found in forms")

            if samesite_cookies:
                print(f"{colored('✓', 'green')} Cookies have SameSite attribute")
            else:
                print(f"{colored('✗', 'red')} Cookies missing SameSite attribute")

            if post_forms:
                print(f"{colored('✓', 'green')} Forms use POST method")
            else:
                print(f"{colored('⚠', 'yellow')} No POST forms detected")

            print(colored("\n╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))

            # Risk assessment
            if not csrf_token_found and not samesite_cookies:
                risk = 'HIGH'
                color = 'red'
            elif not csrf_token_found or not samesite_cookies:
                risk = 'MEDIUM'
                color = 'yellow'
            else:
                risk = 'LOW'
                color = 'green'

            print(f"{colored('RISK ASSESSMENT:', 'yellow')} {colored(risk, color, attrs=['bold'])}")

            if not csrf_token_found:
                print(f"  • Missing CSRF tokens")
            if not samesite_cookies:
                print(f"  • Cookies vulnerable to cross-site requests")

            if risk != 'LOW':
                print(f"\n{colored('RECOMMENDATIONS:', 'yellow')}")
                print(f"  1. Implement CSRF tokens for all state-changing operations")
                print(f"  2. Add SameSite=Strict or SameSite=Lax to session cookies\n")
            else:
                print(f"\n{colored('✓ CSRF protections appear adequate', 'green')}\n")

            return {
                'csrf_token_found': csrf_token_found,
                'samesite_cookies': samesite_cookies,
                'risk': risk
            }

        except Exception as e:
            AsciiArt.error_message(f"CSRF test failed: {str(e)}")
            return {}

    def apiscan(self):
        """API endpoint discovery"""
        print(colored("\n╔═══════════════════ API ENDPOINT DISCOVERY ═══════════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        try:
            print(f"{colored('Scanning for API endpoints...', 'yellow')}\n")

            endpoints = []
            documentation = []

            # Common API paths
            api_paths = ['/api', '/api/v1', '/api/v2', '/graphql', '/swagger', '/api-docs',
                        '/openapi.json', '/swagger.json', '/swagger-ui', '/docs', '/api/docs']

            for path in api_paths:
                try:
                    test_url = f"{self.target.rstrip('/')}{path}"
                    response = requests.get(test_url, timeout=5, verify=False)

                    if response.status_code in [200, 401]:
                        auth_required = 'requires auth' if response.status_code == 401 else 'public'
                        endpoints.append({'path': path, 'status': response.status_code, 'auth': auth_required})

                        # Check if it's documentation
                        if any(doc_word in path.lower() for doc_word in ['swagger', 'docs', 'openapi']):
                            documentation.append(path)

                except:
                    continue

            print(colored("DISCOVERED ENDPOINTS:", 'green', attrs=['bold']))
            if endpoints:
                for ep in endpoints:
                    status_color = 'green' if ep['status'] == 200 else 'yellow'
                    print(f"  {colored('✓', 'green')} {ep['path']} [{colored(ep['status'], status_color)}] ({ep['auth']})")
            else:
                print(f"  {colored('No API endpoints discovered', 'white')}")

            if documentation:
                print(f"\n{colored('DOCUMENTATION FOUND:', 'green', attrs=['bold'])}")
                for doc in documentation:
                    print(f"  {colored('✓', 'green')} {doc}")

            print(colored("\n╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))

            print(f"{colored('SUMMARY:', 'yellow')}")
            print(f"  • Total endpoints: {colored(str(len(endpoints)), 'green')}")
            print(f"  • Public endpoints: {colored(str(sum(1 for e in endpoints if e['auth'] == 'public')), 'green')}")
            print(f"  • Authenticated: {colored(str(sum(1 for e in endpoints if e['auth'] == 'requires auth')), 'yellow')}")
            print(f"  • Documentation available: {colored('Yes' if documentation else 'No', 'green' if documentation else 'white')}\n")

            if documentation:
                print(f"{colored('💡 Tip:', 'blue')} Review {documentation[0]} for full API spec\n")

            return {'endpoints': endpoints, 'documentation': documentation}

        except Exception as e:
            AsciiArt.error_message(f"API scan failed: {str(e)}")
            return {}

    def graphql_introspection(self):
        """GraphQL introspection and schema discovery"""
        print(colored("\n╔═══════════════════ GRAPHQL INTROSPECTION ════════════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        try:
            # Common GraphQL paths
            graphql_paths = ['/graphql', '/api/graphql', '/graphql/v1', '/v1/graphql']

            graphql_endpoint = None
            for path in graphql_paths:
                try:
                    test_url = f"{self.target.rstrip('/')}{path}"
                    response = requests.post(test_url, json={'query': '{__typename}'}, timeout=5, verify=False)
                    if response.status_code in [200, 400] and 'application/json' in response.headers.get('content-type', ''):
                        graphql_endpoint = test_url
                        break
                except:
                    continue

            if not graphql_endpoint:
                AsciiArt.info_message("No GraphQL endpoint found")
                return {}

            print(f"{colored('✓ GraphQL endpoint found:', 'green')} {graphql_endpoint}\n")

            # Try introspection query
            introspection_query = '''{
                __schema {
                    queryType { name }
                    mutationType { name }
                    types {
                        name
                        kind
                    }
                }
            }'''

            response = requests.post(graphql_endpoint, json={'query': introspection_query}, timeout=10, verify=False)

            if response.status_code == 200:
                data = response.json()

                if 'data' in data and '__schema' in data['data']:
                    print(f"{colored('✓ Introspection ENABLED', 'yellow', attrs=['bold'])} (security concern)\n")

                    schema = data['data']['__schema']
                    types = [t['name'] for t in schema.get('types', []) if not t['name'].startswith('__')]

                    print(f"{colored('SCHEMA DISCOVERED:', 'green', attrs=['bold'])}")
                    print(f"  Query Type: {colored(schema.get('queryType', {}).get('name', 'N/A'), 'green')}")
                    print(f"  Mutation Type: {colored(schema.get('mutationType', {}).get('name', 'N/A'), 'green')}")
                    print(f"  Custom Types: {colored(str(len(types)), 'green')}\n")

                    if types:
                        print(f"{colored('SAMPLE TYPES:', 'yellow')}")
                        for t in types[:10]:
                            print(f"  • {t}")
                        if len(types) > 10:
                            print(f"  ... and {len(types) - 10} more\n")

                    print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))
                    print(f"{colored('⚠ Warning:', 'yellow')} Introspection should be disabled in production")
                    print(f"{colored('💡 Tip:', 'blue')} Use full schema for query construction\n")

                    return {'endpoint': graphql_endpoint, 'introspection_enabled': True, 'types': types}
                else:
                    print(f"{colored('✓ Introspection DISABLED', 'green')} (security best practice)\n")
                    print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))
                    return {'endpoint': graphql_endpoint, 'introspection_enabled': False}
            else:
                AsciiArt.error_message("Failed to query GraphQL endpoint")
                return {}

        except Exception as e:
            AsciiArt.error_message(f"GraphQL introspection failed: {str(e)}")
            return {}

    def jwt_scan(self, token=None):
        """JWT token analysis and security testing"""
        print(colored("\n╔═══════════════════ JWT TOKEN ANALYSIS ═══════════════════════════╗", 'red', attrs=['bold']))

        if not token:
            AsciiArt.error_message("No JWT token provided. Usage: jwtscan <token>")
            print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))
            return {}

        try:
            import base64
            import json as json_lib
            from datetime import datetime

            print(f"\n{colored('Token:', 'yellow')} {token[:50]}...\n")

            # Split JWT
            parts = token.split('.')
            if len(parts) != 3:
                AsciiArt.error_message("Invalid JWT format. Expected 3 parts separated by dots.")
                return {}

            # Decode header and payload
            def decode_base64(data):
                # Add padding if needed
                padding = 4 - len(data) % 4
                if padding != 4:
                    data += '=' * padding
                return base64.urlsafe_b64decode(data)

            header = json_lib.loads(decode_base64(parts[0]))
            payload = json_lib.loads(decode_base64(parts[1]))

            # Display header
            print(f"{colored('DECODED HEADER:', 'green', attrs=['bold'])}")
            print(json_lib.dumps(header, indent=2))

            print(f"\n{colored('DECODED PAYLOAD:', 'green', attrs=['bold'])}")
            print(json_lib.dumps(payload, indent=2))

            print(f"\n{colored('SECURITY ANALYSIS:', 'yellow', attrs=['bold'])}")

            # Check algorithm
            alg = header.get('alg', 'none')
            if alg.lower() == 'none':
                print(f"{colored('✗', 'red')} Algorithm: {colored('none (CRITICAL VULNERABILITY)', 'red', attrs=['bold'])}")
            elif alg in ['HS256', 'HS384', 'HS512']:
                print(f"{colored('✓', 'green')} Algorithm: {alg} (symmetric, secure if key is strong)")
            elif alg in ['RS256', 'RS384', 'RS512']:
                print(f"{colored('✓', 'green')} Algorithm: {alg} (asymmetric, secure)")
            else:
                print(f"{colored('⚠', 'yellow')} Algorithm: {alg} (unknown/custom)")

            # Check expiration
            if 'exp' in payload:
                exp_timestamp = payload['exp']
                exp_date = datetime.fromtimestamp(exp_timestamp)
                if datetime.now() > exp_date:
                    print(f"{colored('✗', 'red')} Expired: Token expired on {exp_date}")
                else:
                    days_until_expiry = (exp_date - datetime.now()).days
                    print(f"{colored('✓', 'green')} Not expired (valid until {exp_date}, {days_until_expiry} days remaining)")
            else:
                print(f"{colored('⚠', 'yellow')} No expiration claim found")

            # Check for sensitive data
            sensitive_fields = ['password', 'secret', 'key', 'token', 'api_key']
            sensitive_found = [field for field in sensitive_fields if field in str(payload).lower()]
            if sensitive_found:
                print(f"{colored('✗', 'red')} Sensitive data in payload: {', '.join(sensitive_found)}")
            else:
                print(f"{colored('✓', 'green')} No obvious sensitive data in payload")

            print(colored("\n╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))

            # Risk assessment
            vulnerabilities = []
            if alg.lower() == 'none':
                vulnerabilities.append('Algorithm set to none')
            if 'exp' in payload and datetime.now() > datetime.fromtimestamp(payload['exp']):
                vulnerabilities.append('Token expired')
            if sensitive_found:
                vulnerabilities.append('Sensitive data in payload')

            risk = 'HIGH' if len(vulnerabilities) > 1 else 'MEDIUM' if len(vulnerabilities) == 1 else 'LOW'
            risk_color = 'red' if risk == 'HIGH' else 'yellow' if risk == 'MEDIUM' else 'green'

            print(f"{colored('RISK LEVEL:', 'yellow')} {colored(risk, risk_color, attrs=['bold'])}")
            if vulnerabilities:
                for vuln in vulnerabilities:
                    print(f"  • {vuln}")
            print()

            return {
                'algorithm': alg,
                'payload': payload,
                'vulnerabilities': vulnerabilities,
                'risk': risk
            }

        except Exception as e:
            AsciiArt.error_message(f"JWT analysis failed: {str(e)}")
            return {}
