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

    def webscan(self):
        """Complete web vulnerability scan"""
        print(f"\n{colored('Starting comprehensive web scan...', 'cyan', attrs=['bold'])}")
        print(AsciiArt.tool_category_banner('web'))
        
        results = {}
        
        # Run all scans
        print(f"\n{colored('[1/8] Security Headers Analysis', 'yellow')}")
        results['headers'] = self.headers_scan()
        
        print(f"\n{colored('[2/8] SSL/TLS Configuration', 'yellow')}")
        results['ssl'] = self.ssl_scan()
        
        print(f"\n{colored('[3/8] WAF Detection', 'yellow')}")
        results['waf'] = self.waf_detect()
        
        print(f"\n{colored('[4/8] CMS Detection', 'yellow')}")
        results['cms'] = self.cms_detect()
        
        print(f"\n{colored('[5/8] Cookie Security', 'yellow')}")
        results['cookies'] = self.cookie_scan()
        
        print(f"\n{colored('[6/8] CORS Configuration', 'yellow')}")
        results['cors'] = self.cors_test()
        
        print(f"\n{colored('[7/8] XSS Testing', 'yellow')}")
        results['xss'] = self.xss_test()
        
        print(f"\n{colored('[8/8] SQL Injection Testing', 'yellow')}")
        results['sql'] = self.sql_injection_test()
        
        AsciiArt.success_message("Web scan complete! Use 'results' to view findings.")
        return results

    def dir_scan(self):
        """Directory and file enumeration"""
        print(f"\n{colored('Starting directory enumeration...', 'cyan')}")
        
        # Common paths to check
        common_paths = [
            'admin', 'administrator', 'login', 'dashboard', 'panel',
            'wp-admin', 'phpmyadmin', 'backup', 'backups', 'config',
            'api', 'test', 'dev', 'staging', 'uploads', 'images',
            '.git', '.env', '.htaccess', 'web.config', 'robots.txt',
            'sitemap.xml', 'crossdomain.xml', 'phpinfo.php'
        ]
        
        found = []
        base_url = self.target.rstrip('/')
        
        print(f"\n{colored('Checking common paths...', 'yellow')}")
        
        for path in common_paths:
            url = f"{base_url}/{path}"
            try:
                response = requests.get(url, timeout=3, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    status_color = 'green' if response.status_code == 200 else 'yellow'
                    print(f"{colored('✓', status_color)} {url} [{response.status_code}]")
                    found.append({'url': url, 'status': response.status_code})
            except:
                pass
        
        if found:
            AsciiArt.success_message(f"Found {len(found)} accessible paths")
        else:
            AsciiArt.info_message("No common paths found")
        
        return found

    def sql_injection_test(self):
        """Test for SQL injection vulnerabilities"""
        print(f"\n{colored('Testing for SQL injection...', 'cyan')}")
        
        # SQL injection payloads
        payloads = [
            "'", "\"", "1' OR '1'='1", "1' OR '1'='1' --", "admin'--",
            "1' UNION SELECT NULL--", "1' AND 1=1--", "1' AND 1=2--"
        ]
        
        vulnerabilities = []
        
        try:
            # Get a baseline response
            response_baseline = requests.get(self.target, timeout=10)
            baseline_length = len(response_baseline.text)
            
            print(f"\n{colored('Testing payloads...', 'yellow')}")
            
            for payload in payloads:
                try:
                    # Test in URL parameter
                    test_url = f"{self.target}{'&' if '?' in self.target else '?'}id={payload}"
                    response = requests.get(test_url, timeout=5)
                    
                    # Check for SQL errors
                    sql_errors = [
                        'mysql', 'sql syntax', 'postgresql', 'ora-', 'sqlite',
                        'microsoft sql', 'jdbc', 'odbc', 'warning: mysql'
                    ]
                    
                    if any(error in response.text.lower() for error in sql_errors):
                        print(f"{colored('!', 'red')} Potential SQLi: {payload[:30]}")
                        vulnerabilities.append(payload)
                    
                    # Check for significant response differences
                    elif abs(len(response.text) - baseline_length) > 100:
                        print(f"{colored('?', 'yellow')} Unusual response: {payload[:30]}")
                        
                except:
                    pass
            
            if vulnerabilities:
                AsciiArt.warning_message(f"Potential SQL injection found! {len(vulnerabilities)} payloads triggered errors")
            else:
                AsciiArt.success_message("No obvious SQL injection vulnerabilities detected")
            
            return vulnerabilities
            
        except Exception as e:
            AsciiArt.error_message(f"SQL injection test failed: {str(e)}")
            return []

    def xss_test(self):
        """Test for XSS vulnerabilities"""
        print(f"\n{colored('Testing for XSS vulnerabilities...', 'cyan')}")
        
        # XSS payloads
        payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(String.fromCharCode(88,83,83))</script>',
            '<svg/onload=alert(1)>',
            'javascript:alert(1)'
        ]
        
        vulnerabilities = []
        
        try:
            print(f"\n{colored('Testing payloads...', 'yellow')}")
            
            for payload in payloads:
                try:
                    # Test in URL parameter
                    test_url = f"{self.target}{'&' if '?' in self.target else '?'}q={payload}"
                    response = requests.get(test_url, timeout=5)
                    
                    # Check if payload is reflected
                    if payload in response.text:
                        print(f"{colored('!', 'red')} Reflected: {payload[:40]}")
                        vulnerabilities.append(payload)
                        
                except:
                    pass
            
            if vulnerabilities:
                AsciiArt.warning_message(f"Potential XSS found! {len(vulnerabilities)} payloads reflected")
            else:
                AsciiArt.success_message("No obvious XSS vulnerabilities detected")
            
            return vulnerabilities
            
        except Exception as e:
            AsciiArt.error_message(f"XSS test failed: {str(e)}")
            return []

    def csrf_test(self):
        """Test for CSRF vulnerabilities"""
        print(f"\n{colored('Testing CSRF protection...', 'cyan')}")
        
        try:
            response = requests.get(self.target, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            print(f"\n{colored(f'Found {len(forms)} forms', 'yellow')}")
            
            vulnerable_forms = []
            
            for i, form in enumerate(forms[:5], 1):
                action = form.get('action', 'N/A')
                method = form.get('method', 'GET').upper()
                
                # Check for CSRF tokens
                csrf_fields = ['csrf', 'token', '_token', 'authenticity_token']
                has_csrf = any(
                    inp.get('name', '').lower().find(field) != -1
                    for inp in form.find_all('input')
                    for field in csrf_fields
                )
                
                status = colored('✓ Protected', 'green') if has_csrf else colored('✗ No CSRF token', 'red')
                print(f"\nForm #{i}: {method} {action}")
                print(f"  CSRF Protection: {status}")
                
                if not has_csrf and method == 'POST':
                    vulnerable_forms.append({'action': action, 'method': method})
            
            if vulnerable_forms:
                AsciiArt.warning_message(f"{len(vulnerable_forms)} forms lack CSRF protection!")
            else:
                AsciiArt.success_message("All forms appear to have CSRF protection")
            
            return vulnerable_forms
            
        except Exception as e:
            AsciiArt.error_message(f"CSRF test failed: {str(e)}")
            return []

    def cookie_scan(self):
        """Analyze cookie security"""
        print(f"\n{colored('Analyzing cookies...', 'cyan')}")
        
        try:
            response = requests.get(self.target, timeout=10)
            cookies = response.cookies
            
            if not cookies:
                AsciiArt.info_message("No cookies set by the server")
                return []
            
            print(f"\n{colored(f'Found {len(cookies)} cookies', 'yellow')}")
            
            issues = []
            
            for cookie in cookies:
                print(f"\n{colored('Cookie:', 'cyan')} {cookie.name}")
                print(f"  Value: {cookie.value[:50]}...")
                
                # Security flags
                flags = []
                if cookie.secure:
                    flags.append(colored('Secure', 'green'))
                else:
                    flags.append(colored('No Secure', 'red'))
                    issues.append(f"{cookie.name}: Missing Secure flag")
                
                if cookie.has_nonstandard_attr('HttpOnly'):
                    flags.append(colored('HttpOnly', 'green'))
                else:
                    flags.append(colored('No HttpOnly', 'red'))
                    issues.append(f"{cookie.name}: Missing HttpOnly flag")
                
                if cookie.has_nonstandard_attr('SameSite'):
                    flags.append(colored('SameSite', 'green'))
                else:
                    flags.append(colored('No SameSite', 'yellow'))
                
                print(f"  Flags: {', '.join(flags)}")
            
            if issues:
                AsciiArt.warning_message(f"Found {len(issues)} cookie security issues")
            else:
                AsciiArt.success_message("Cookie security looks good!")
            
            return issues
            
        except Exception as e:
            AsciiArt.error_message(f"Cookie scan failed: {str(e)}")
            return []

    def cors_test(self):
        """Test CORS configuration"""
        print(f"\n{colored('Testing CORS configuration...', 'cyan')}")
        
        test_origins = [
            'https://evil.com',
            'null',
            self.target
        ]
        
        issues = []
        
        try:
            for origin in test_origins:
                headers = {'Origin': origin}
                response = requests.get(self.target, headers=headers, timeout=10)
                
                acao = response.headers.get('Access-Control-Allow-Origin')
                acac = response.headers.get('Access-Control-Allow-Credentials')
                
                if acao:
                    print(f"\n{colored('Origin:', 'yellow')} {origin}")
                    print(f"  ACAO: {colored(acao, 'cyan')}")
                    
                    if acao == '*':
                        AsciiArt.warning_message("Wildcard CORS - allows all origins!")
                        issues.append("Wildcard CORS enabled")
                    elif acao == origin and origin != self.target:
                        AsciiArt.warning_message(f"CORS reflects origin: {origin}")
                        issues.append(f"CORS reflects untrusted origin: {origin}")
                    
                    if acac:
                        print(f"  Credentials: {colored('Allowed', 'red')}")
                        if acao == '*':
                            issues.append("Dangerous: Wildcard CORS with credentials")
            
            if not issues:
                AsciiArt.success_message("CORS configuration appears secure")
            
            return issues
            
        except Exception as e:
            AsciiArt.error_message(f"CORS test failed: {str(e)}")
            return []

    def open_redirect_test(self):
        """Test for open redirect vulnerabilities"""
        print(f"\n{colored('Testing for open redirects...', 'cyan')}")
        
        redirect_params = ['url', 'redirect', 'next', 'return', 'redir', 'dest', 'destination', 'goto']
        test_url = 'https://evil.com'
        
        vulnerabilities = []
        
        try:
            for param in redirect_params:
                test_target = f"{self.target}{'&' if '?' in self.target else '?'}{param}={test_url}"
                
                try:
                    response = requests.get(test_target, timeout=5, allow_redirects=False)
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if test_url in location:
                            print(f"{colored('!', 'red')} Redirect found: {param}={test_url}")
                            vulnerabilities.append(param)
                except:
                    pass
            
            if vulnerabilities:
                AsciiArt.warning_message(f"Potential open redirect! Parameters: {', '.join(vulnerabilities)}")
            else:
                AsciiArt.success_message("No open redirect vulnerabilities detected")
            
            return vulnerabilities
            
        except Exception as e:
            AsciiArt.error_message(f"Open redirect test failed: {str(e)}")
            return []

    def ssrf_test(self):
        """Test for SSRF vulnerabilities"""
        print(f"\n{colored('Testing for SSRF...', 'cyan')}")
        
        # SSRF test payloads
        payloads = [
            'http://127.0.0.1',
            'http://localhost',
            'http://169.254.169.254',  # AWS metadata
            'http://metadata.google.internal',  # GCP metadata
            'file:///etc/passwd'
        ]
        
        url_params = ['url', 'uri', 'path', 'file', 'page', 'fetch', 'src', 'source']
        
        findings = []
        
        try:
            for param in url_params:
                for payload in payloads:
                    test_url = f"{self.target}{'&' if '?' in self.target else '?'}{param}={payload}"
                    
                    try:
                        response = requests.get(test_url, timeout=5)
                        
                        # Look for signs of internal access
                        indicators = ['root:', 'localhost', 'metadata', '127.0.0.1']
                        if any(ind in response.text.lower() for ind in indicators):
                            print(f"{colored('!', 'red')} Potential SSRF: {param}={payload}")
                            findings.append({'param': param, 'payload': payload})
                    except:
                        pass
            
            if findings:
                AsciiArt.warning_message(f"Potential SSRF vulnerabilities found!")
            else:
                AsciiArt.success_message("No obvious SSRF vulnerabilities detected")
            
            return findings
            
        except Exception as e:
            AsciiArt.error_message(f"SSRF test failed: {str(e)}")
            return []

    def lfi_test(self):
        """Test for Local File Inclusion"""
        print(f"\n{colored('Testing for LFI...', 'cyan')}")
        
        lfi_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '/etc/passwd',
            'C:\\windows\\win.ini'
        ]
        
        file_params = ['file', 'page', 'include', 'path', 'doc', 'document']
        
        vulnerabilities = []
        
        try:
            for param in file_params:
                for payload in lfi_payloads:
                    test_url = f"{self.target}{'&' if '?' in self.target else '?'}{param}={payload}"
                    
                    try:
                        response = requests.get(test_url, timeout=5)
                        
                        # Check for file content indicators
                        if 'root:' in response.text or '[extensions]' in response.text.lower():
                            print(f"{colored('!', 'red')} LFI found: {param}={payload[:30]}")
                            vulnerabilities.append({'param': param, 'payload': payload})
                    except:
                        pass
            
            if vulnerabilities:
                AsciiArt.warning_message(f"Potential LFI vulnerabilities found!")
            else:
                AsciiArt.success_message("No obvious LFI vulnerabilities detected")
            
            return vulnerabilities
            
        except Exception as e:
            AsciiArt.error_message(f"LFI test failed: {str(e)}")
            return []

    def rfi_test(self):
        """Test for Remote File Inclusion"""
        print(f"\n{colored('Testing for RFI...', 'cyan')}")
        
        # Use a safe test URL
        test_url = 'https://raw.githubusercontent.com/cybersecurity/test/main/test.txt'
        file_params = ['file', 'page', 'include', 'path', 'url']
        
        vulnerabilities = []
        
        try:
            for param in file_params:
                test_target = f"{self.target}{'&' if '?' in self.target else '?'}{param}={test_url}"
                
                try:
                    response = requests.get(test_target, timeout=5)
                    
                    # Check if external content was loaded
                    if 'test-content' in response.text or len(response.text) > 1000:
                        print(f"{colored('!', 'red')} Potential RFI: {param}")
                        vulnerabilities.append(param)
                except:
                    pass
            
            if vulnerabilities:
                AsciiArt.warning_message(f"Potential RFI vulnerabilities found!")
            else:
                AsciiArt.success_message("No obvious RFI vulnerabilities detected")
            
            return vulnerabilities
            
        except Exception as e:
            AsciiArt.error_message(f"RFI test failed: {str(e)}")
            return []

    def xxe_test(self):
        """Test for XXE vulnerabilities"""
        print(f"\n{colored('Testing for XXE...', 'cyan')}")
        
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>'''
        
        try:
            # Test XML endpoints
            response = requests.post(
                self.target,
                data=xxe_payload,
                headers={'Content-Type': 'application/xml'},
                timeout=5
            )
            
            if 'root:' in response.text:
                AsciiArt.warning_message("Potential XXE vulnerability detected!")
                return True
            else:
                AsciiArt.success_message("No obvious XXE vulnerabilities detected")
                return False
                
        except Exception as e:
            AsciiArt.info_message("XXE test completed (no XML endpoint found)")
            return False

    def api_scan(self):
        """Discover API endpoints"""
        print(f"\n{colored('Scanning for API endpoints...', 'cyan')}")
        
        api_paths = [
            'api', 'api/v1', 'api/v2', 'rest', 'graphql',
            'api/users', 'api/auth', 'api/login', 'api/admin',
            'v1', 'v2', 'v3', 'swagger', 'api-docs', 'openapi.json'
        ]
        
        found_endpoints = []
        base_url = self.target.rstrip('/')
        
        print(f"\n{colored('Checking common API paths...', 'yellow')}")
        
        for path in api_paths:
            url = f"{base_url}/{path}"
            try:
                response = requests.get(url, timeout=3)
                if response.status_code in [200, 401, 403]:
                    print(f"{colored('✓', 'green')} {url} [{response.status_code}]")
                    found_endpoints.append({'url': url, 'status': response.status_code})
                    
                    # Check if it's JSON
                    try:
                        data = response.json()
                        print(f"  {colored('JSON response detected', 'cyan')}")
                    except:
                        pass
            except:
                pass
        
        if found_endpoints:
            AsciiArt.success_message(f"Found {len(found_endpoints)} API endpoints")
        else:
            AsciiArt.info_message("No common API endpoints found")
        
        return found_endpoints

    def graphql_test(self):
        """Test GraphQL introspection"""
        print(f"\n{colored('Testing GraphQL endpoint...', 'cyan')}")
        
        introspection_query = {
            'query': '''
                {
                    __schema {
                        types {
                            name
                            fields {
                                name
                            }
                        }
                    }
                }
            '''
        }
        
        graphql_paths = ['graphql', 'api/graphql', 'v1/graphql', 'query']
        base_url = self.target.rstrip('/')
        
        for path in graphql_paths:
            url = f"{base_url}/{path}"
            try:
                response = requests.post(url, json=introspection_query, timeout=5)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data and '__schema' in data['data']:
                            print(f"{colored('✓', 'green')} GraphQL found: {url}")
                            print(f"{colored('!', 'yellow')} Introspection is ENABLED")
                            
                            types = data['data']['__schema']['types']
                            print(f"\n{colored('Schema Types:', 'cyan')}")
                            for t in types[:10]:
                                print(f"  • {t['name']}")
                            
                            AsciiArt.warning_message("GraphQL introspection enabled - schema is exposed!")
                            return data
                    except:
                        pass
            except:
                pass
        
        AsciiArt.info_message("No GraphQL endpoint found")
        return None

    def jwt_scan(self):
        """Analyze JWT tokens"""
        print(f"\n{colored('Scanning for JWT tokens...', 'cyan')}")
        
        try:
            response = requests.get(self.target, timeout=10)
            
            # Check cookies and headers for JWTs
            jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
            
            import re
            found_jwts = []
            
            # Check in response
            tokens = re.findall(jwt_pattern, response.text)
            found_jwts.extend(tokens)
            
            # Check in cookies
            for cookie in response.cookies:
                if re.match(jwt_pattern, cookie.value):
                    found_jwts.append(cookie.value)
            
            if found_jwts:
                print(f"\n{colored(f'Found {len(found_jwts)} JWT token(s)', 'yellow')}")
                
                import base64
                import json as json_lib
                
                for i, token in enumerate(found_jwts[:3], 1):
                    print(f"\n{colored(f'Token #{i}:', 'cyan')}")
                    print(f"  {token[:50]}...")
                    
                    try:
                        # Decode header and payload
                        parts = token.split('.')
                        if len(parts) == 3:
                            header = json_lib.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                            payload = json_lib.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                            
                            print(f"\n  {colored('Algorithm:', 'yellow')} {header.get('alg')}")
                            print(f"  {colored('Payload:', 'yellow')} {list(payload.keys())[:5]}")
                            
                            # Security checks
                            if header.get('alg') == 'none':
                                AsciiArt.warning_message("  Algorithm 'none' - CRITICAL vulnerability!")
                            if header.get('alg') in ['HS256', 'HS384', 'HS512']:
                                AsciiArt.info_message("  Using HMAC - vulnerable to key confusion")
                    except:
                        print(f"  {colored('Could not decode', 'red')}")
                
                return found_jwts
            else:
                AsciiArt.info_message("No JWT tokens found")
                return []
                
        except Exception as e:
            AsciiArt.error_message(f"JWT scan failed: {str(e)}")
            return []
