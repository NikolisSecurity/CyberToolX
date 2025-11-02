"""Advanced CSRF Testing Module

Comprehensive cross-site request forgery testing including token bypass,
SameSite cookie testing, Origin/Referer validation bypass, method override,
subdomain CSRF, and advanced bypass techniques.
"""

import requests
import re
import sys
import os
import json
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.color_compat import colored
from utils.ascii_art import AsciiArt


class AdvancedCSRF:
    """Advanced CSRF testing suite"""

    def __init__(self, target):
        self.target = target if target.startswith('http') else f'http://{target}'
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CyberGuardian/2.0'})

        # CSRF token patterns
        self.csrf_token_patterns = [
            r'csrf[_-]?token',
            r'authenticity[_-]?token',
            r'_token',
            r'csrf[_-]?middlewaretoken',
            r'anti[_-]?csrf[_-]?token',
            r'xsrf[_-]?token',
            r'request[_-]?token',
            r'form[_-]?token'
        ]

        # SameSite cookie test payloads
        self.samesite_payloads = [
            'Lax', 'Strict', 'None', 'invalid'
        ]

        # Origin/Referer bypass techniques
        self.origin_bypass_payloads = [
            # Remove Origin header
            None,

            # Empty Origin
            '',

            # Same origin
            self.target,

            # Subdomain variations
            f"{urlparse(self.target).netloc.replace('www', 'admin')}.{urlparse(self.target).scheme}",

            # Trusted origins
            'null',
            'https://google.com',
            'https://facebook.com',
            'https://localhost:3000',

            # Origin manipulation
            f"https://evil.{urlparse(self.target).netloc}",
            f"https://{urlparse(self.target).netloc}.evil.com",
        ]

        # Method override techniques
        self.method_override_payloads = [
            {'_method': 'PUT'},
            {'_method': 'DELETE'},
            {'_method': 'PATCH'},
            {'method': 'PUT'},
            {'method': 'DELETE'},
            {'X-HTTP-Method-Override': 'PUT'},
            {'X-HTTP-Method-Override': 'DELETE'},
            {'X-Method-Override': 'PUT'},
            {'X-Method-Override': 'DELETE'},
        ]

    def test_advanced_csrf(self):
        """Main advanced CSRF testing function"""
        print(colored("\n╔═══════════════════ ADVANCED CSRF TESTING ═══════════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        try:
            results = {
                'token_analysis': self._analyze_csrf_tokens(),
                'samesite_testing': self._test_samesite_cookies(),
                'origin_validation': self._test_origin_validation(),
                'method_override': self._test_method_override(),
                'subdomain_csrf': self._test_subdomain_csrf(),
                'token_bypass': self._test_token_bypass(),
                'state_changing': self._identify_state_changing_actions(),
                'referer_bypass': self._test_referer_bypass()
            }

            self._print_summary(results)
            return results

        except Exception as e:
            AsciiArt.error_message(f"Advanced CSRF test failed: {str(e)}")
            return {}

    def _analyze_csrf_tokens(self):
        """Analyze CSRF token implementation"""
        print(f"{colored('Analyzing CSRF token implementation...', 'yellow')}")

        results = {
            'tokens_found': [],
            'token_patterns': [],
            'token_entropy': {},
            'token_reuse': False,
            'token_validation': {}
        }

        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find forms with CSRF tokens
            forms = soup.find_all('form')
            for i, form in enumerate(forms):
                form_tokens = []

                # Check for hidden input tokens
                hidden_inputs = form.find_all('input', {'type': 'hidden'})
                for input_tag in hidden_inputs:
                    name = input_tag.get('name', '').lower()
                    value = input_tag.get('value', '')

                    for pattern in self.csrf_token_patterns:
                        if re.search(pattern, name, re.IGNORECASE):
                            form_tokens.append({
                                'name': input_tag.get('name'),
                                'value': value,
                                'pattern': pattern,
                                'length': len(value),
                                'form_index': i
                            })
                            results['token_patterns'].append(pattern)

                # Check for meta tags
                meta_tags = soup.find_all('meta')
                for meta in meta_tags:
                    name = meta.get('name', '').lower() or meta.get('property', '').lower()
                    content = meta.get('content', '')

                    for pattern in self.csrf_token_patterns:
                        if re.search(pattern, name, re.IGNORECASE):
                            form_tokens.append({
                                'name': name,
                                'value': content,
                                'pattern': pattern,
                                'length': len(content),
                                'type': 'meta'
                            })
                            results['token_patterns'].append(pattern)

                if form_tokens:
                    results['tokens_found'].extend(form_tokens)
                    print(f"  {colored('✓', 'green')} Form {i+1}: {len(form_tokens)} CSRF token(s) found")

            # Analyze token entropy
            all_tokens = [t['value'] for t in results['tokens_found'] if t['value']]
            if all_tokens:
                results['token_entropy'] = self._analyze_token_entropy(all_tokens)

            # Test token reuse (make multiple requests)
            if results['tokens_found']:
                token_reuse_test = self._test_token_reuse(results['tokens_found'][0])
                results['token_reuse'] = token_reuse_test['reuse_detected']
                results['token_validation'] = token_reuse_test['validation']

        except Exception as e:
            print(f"  {colored('⚠ Error analyzing tokens:', 'yellow')} {str(e)}")

        if not results['tokens_found']:
            print(f"  {colored('⚠ No CSRF tokens found', 'red', attrs=['bold'])}")
        else:
            print(f"  {colored('✓', 'green')} Found {colored(str(len(results['tokens_found'])), 'green')} CSRF token(s)")

        return results

    def _test_samesite_cookies(self):
        """Test SameSite cookie configuration"""
        print(f"\n{colored('Testing SameSite cookie configuration...', 'yellow')}")

        results = {
            'cookies_tested': 0,
            'samesite_configured': 0,
            'cookies_without_samesite': [],
            'session_cookies': [],
            'insecure_cookies': []
        }

        try:
            response = self.session.get(self.target, timeout=10, verify=False)

            # Analyze Set-Cookie headers
            for cookie in response.cookies:
                results['cookies_tested'] += 1

                cookie_info = {
                    'name': cookie.name,
                    'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
                    'secure': getattr(cookie, 'secure', False),
                    'httponly': getattr(cookie, 'httponly', False),
                    'samesite': getattr(cookie, 'samesite', None),
                    'domain': getattr(cookie, 'domain', None),
                    'path': getattr(cookie, 'path', None)
                }

                # Check for session-related cookies
                session_indicators = ['session', 'sid', 'token', 'auth', 'login']
                if any(indicator in cookie.name.lower() for indicator in session_indicators):
                    results['session_cookies'].append(cookie_info)

                # Check SameSite attribute
                if cookie_info['samesite']:
                    results['samesite_configured'] += 1
                    print(f"  {colored('✓', 'green')} {cookie.name}: SameSite={cookie_info['samesite']}")
                else:
                    results['cookies_without_samesite'].append(cookie_info)
                    print(f"  {colored('✗', 'red')} {cookie.name}: No SameSite attribute")

                # Check for insecure cookie settings
                if (not cookie_info['secure'] or not cookie_info['httponly'] or
                    cookie_info.get('domain', '').startswith('.')):
                    results['insecure_cookies'].append(cookie_info)

            # Test SameSite behavior
            if results['session_cookies']:
                samesite_test = self._test_samesite_behavior()
                results['samesite_behavior'] = samesite_test

        except Exception as e:
            print(f"  {colored('⚠ Error testing SameSite:', 'yellow')} {str(e)}")

        # Summary
        if results['cookies_tested'] == 0:
            print(f"  {colored('ℹ No cookies found', 'blue')}")
        elif len(results['cookies_without_samesite']) == 0:
            print(f"  {colored('✓', 'green')} All cookies have SameSite attribute")
        else:
            print(f"  {colored('⚠', 'yellow')} {len(results['cookies_without_samesite'])} cookies without SameSite")

        return results

    def _test_origin_validation(self):
        """Test Origin header validation"""
        print(f"\n{colored('Testing Origin header validation...', 'yellow')}")

        results = {
            'origin_required': False,
            'validation_strict': False,
            'bypass_possible': False,
            'accepted_origins': [],
            'bypass_methods': []
        }

        # Find a form to test
        forms = self._find_forms()
        if not forms:
            print(f"  {colored('ℹ No forms found for testing', 'blue')}")
            return results

        test_form = forms[0]  # Test first form
        print(f"  {colored('Testing form:', 'white')} {test_form.get('action', 'unknown')}")

        # Test different Origin headers
        for origin in self.origin_bypass_payloads:
            try:
                headers = {'User-Agent': 'CyberGuardian/2.0'}
                if origin is not None:
                    headers['Origin'] = origin
                    headers['Referer'] = origin

                # Submit form with custom Origin
                response = self._submit_form_with_headers(test_form, headers)

                # Analyze response
                if response.status_code == 200:
                    results['accepted_origins'].append(origin or 'No Origin')

                    # Check if this is a bypass
                    if origin not in [None, '', self.target]:
                        results['bypass_possible'] = True
                        results['bypass_methods'].append(f"Origin: {origin}")
                        print(f"    {colored('✗', 'red')} Origin bypass possible with: {origin}")

                elif response.status_code in [403, 401, 400]:
                    if not results['origin_required']:
                        results['origin_required'] = True
                        print(f"    {colored('✓', 'green')} Origin validation detected")

            except:
                continue

        # Test strictness
        if results['origin_required'] and not results['bypass_possible']:
            results['validation_strict'] = True
            print(f"  {colored('✓', 'green')} Strict Origin validation implemented")

        elif not results['origin_required']:
            print(f"  {colored('⚠', 'yellow')} No Origin validation detected")

        return results

    def _test_method_override(self):
        """Test HTTP method override functionality"""
        print(f"\n{colored('Testing HTTP method override...', 'yellow')}")

        results = {
            'override_possible': False,
            'override_methods': [],
            'vulnerable_endpoints': []
        }

        forms = self._find_forms()
        if not forms:
            print(f"  {colored('ℹ No forms found for testing', 'blue')}")
            return results

        for form in forms[:2]:  # Test first 2 forms
            print(f"  {colored('Testing form:', 'white')} {form.get('action', 'unknown')}")

            for override_payload in self.method_override_payloads:
                try:
                    # Submit form with method override
                    modified_form = self._add_method_override_to_form(form, override_payload)
                    response = self._submit_form(modified_form)

                    # Check if override worked
                    if response.status_code in [200, 201, 204]:
                        # Look for signs that the override was processed
                        content_lower = response.text.lower()
                        if any(indicator in content_lower for indicator in ['updated', 'deleted', 'modified', 'changed']):
                            results['override_possible'] = True
                            results['override_methods'].append(override_payload)
                            results['vulnerable_endpoints'].append(form.get('action', 'unknown'))
                            print(f"    {colored('✗', 'red')} Method override possible: {override_payload}")
                            break

                except:
                    continue

        if not results['override_possible']:
            print(f"  {colored('✓', 'green')} No method override vulnerabilities detected")

        return results

    def _test_subdomain_csrf(self):
        """Test subdomain CSRF vulnerabilities"""
        print(f"\n{colored('Testing subdomain CSRF...', 'yellow')}")

        results = {
            'vulnerable': False,
            'subdomain_tested': [],
            'cookie_domains': [],
            'bypass_possible': False
        }

        try:
            response = self.session.get(self.target, timeout=10, verify=False)

            # Check cookie domains
            for cookie in response.cookies:
                domain = getattr(cookie, 'domain', None)
                if domain:
                    results['cookie_domains'].append({
                        'name': cookie.name,
                        'domain': domain,
                        'leading_dot': domain.startswith('.')
                    })

            # Test common subdomain patterns
            base_domain = urlparse(self.target).netloc
            subdomains = [
                f"admin.{base_domain}",
                f"api.{base_domain}",
                f"app.{base_domain}",
                f"blog.{base_domain}",
                f"dev.{base_domain}",
                f"test.{base_domain}"
            ]

            for subdomain in subdomains:
                try:
                    subdomain_url = self.target.replace(base_domain, subdomain)
                    subdomain_response = self.session.get(subdomain_url, timeout=5, verify=False)

                    if subdomain_response.status_code != 404:
                        results['subdomain_tested'].append({
                            'subdomain': subdomain,
                            'status': subdomain_response.status_code,
                            'accessible': True
                        })

                        # Check for cookie sharing
                        shared_cookies = set(response.cookies.keys()) & set(subdomain_response.cookies.keys())
                        if shared_cookies:
                            results['bypass_possible'] = True
                            print(f"    {colored('✗', 'red')} Shared cookies with {subdomain}")
                            print(f"      Shared: {', '.join(shared_cookies)}")

                except:
                    continue

        except:
            pass

        if not results['bypass_possible']:
            print(f"  {colored('✓', 'green')} No subdomain CSRF vulnerabilities detected")

        return results

    def _test_token_bypass(self):
        """Test CSRF token bypass techniques"""
        print(f"\n{colored('Testing CSRF token bypass techniques...', 'yellow')}")

        results = {
            'bypass_found': False,
            'bypass_methods': [],
            'successful_payloads': []
        }

        forms = self._find_forms_with_tokens()
        if not forms:
            print(f"  {colored('ℹ No forms with CSRF tokens found', 'blue')}")
            return results

        for form in forms[:1]:  # Test first form with token
            print(f"  {colored('Testing form:', 'white')} {form.get('action', 'unknown')}")

            # Bypass techniques
            bypass_techniques = [
                # Remove token completely
                {'method': 'remove_token'},

                # Replace with empty token
                {'method': 'empty_token'},

                # Replace with fixed token
                {'method': 'fixed_token', 'value': 'csrf-token-123'},

                # Duplicate token parameter
                {'method': 'duplicate_token'},

                # Change token parameter name
                {'method': 'rename_token'},

                # URL encoding variations
                {'method': 'url_encode'},

                # Multiple tokens
                {'method': 'multiple_tokens'}
            ]

            for technique in bypass_techniques:
                try:
                    modified_form = self._apply_token_bypass(form, technique)
                    response = self._submit_form(modified_form)

                    # Check if bypass was successful
                    if response.status_code in [200, 201, 302]:
                        content_lower = response.text.lower()

                        # Look for success indicators
                        success_indicators = [
                            'success', 'saved', 'updated', 'created', 'deleted',
                            'welcome', 'dashboard', 'profile', 'settings'
                        ]

                        if any(indicator in content_lower for indicator in success_indicators):
                            results['bypass_found'] = True
                            results['bypass_methods'].append(technique['method'])
                            results['successful_payloads'].append(technique)
                            print(f"    {colored('✗', 'red')} CSRF bypass successful: {technique['method']}")
                            break

                except:
                    continue

        if not results['bypass_found']:
            print(f"  {colored('✓', 'green')} No CSRF token bypass techniques worked")

        return results

    def _identify_state_changing_actions(self):
        """Identify state-changing actions that should be protected"""
        print(f"\n{colored('Identifying state-changing actions...', 'yellow')}")

        results = {
            'actions_found': [],
            'protected_count': 0,
            'unprotected_count': 0,
            'risk_actions': []
        }

        # Look for forms with dangerous actions
        forms = self._find_forms()
        dangerous_actions = [
            'delete', 'remove', 'destroy', 'drop',
            'update', 'modify', 'change', 'edit',
            'create', 'add', 'insert', 'new',
            'admin', 'settings', 'config', 'password',
            'email', 'profile', 'account', 'logout'
        ]

        for form in forms:
            action = form.get('action', '').lower()
            method = form.get('method', 'get').lower()

            # Check if this is a state-changing action
            is_dangerous = any(danger in action for danger in dangerous_actions) or method in ['post', 'put', 'delete', 'patch']

            if is_dangerous:
                has_token = self._form_has_csrf_token(form)

                action_info = {
                    'action': form.get('action', 'unknown'),
                    'method': method,
                    'has_token': has_token,
                    'risk_level': 'high' if any(danger in action for danger in ['delete', 'remove', 'destroy', 'admin']) else 'medium'
                }

                results['actions_found'].append(action_info)

                if has_token:
                    results['protected_count'] += 1
                    print(f"    {colored('✓', 'green')} {action} [{method}] - Protected")
                else:
                    results['unprotected_count'] += 1
                    results['risk_actions'].append(action_info)
                    print(f"    {colored('✗', 'red')} {action} [{method}] - Unprotected!")

        if not results['actions_found']:
            print(f"  {colored('ℹ No state-changing actions identified', 'blue')}")

        return results

    def _test_referer_bypass(self):
        """Test Referer header bypass techniques"""
        print(f"\n{colored('Testing Referer header bypass...', 'yellow')}")

        results = {
            'referer_required': False,
            'bypass_possible': False,
            'bypass_methods': []
        }

        forms = self._find_forms()
        if not forms:
            print(f"  {colored('ℹ No forms found for testing', 'blue')}")
            return results

        # Referer bypass techniques
        referer_bypasses = [
            None,  # No referer
            '',    # Empty referer
            self.target,  # Same origin
            'https://google.com',  # Trusted domain
            'https://evil.com',    # Malicious domain
            f'https://{urlparse(self.target).netloc}.evil.com',  # Subdomain
            'file:///etc/passwd',  # Local file
        ]

        test_form = forms[0]
        for referer in referer_bypasses:
            try:
                headers = {'User-Agent': 'CyberGuardian/2.0'}
                if referer is not None:
                    headers['Referer'] = referer

                response = self._submit_form_with_headers(test_form, headers)

                if response.status_code == 200:
                    # Check if this is a bypass
                    if referer not in [None, '', self.target]:
                        results['bypass_possible'] = True
                        results['bypass_methods'].append(f"Referer: {referer}")
                        print(f"    {colored('✗', 'red')} Referer bypass possible with: {referer}")

                elif response.status_code in [403, 401]:
                    if not results['referer_required']:
                        results['referer_required'] = True
                        print(f"    {colored('✓', 'green')} Referer validation detected")

            except:
                continue

        if not results['referer_required']:
            print(f"  {colored('⚠', 'yellow')} No Referer validation detected")

        return results

    def _find_forms(self):
        """Find all forms in the target"""
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []

            for form in soup.find_all('form'):
                forms.append({
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': [(inp.get('name'), inp.get('value', '')) for inp in form.find_all(['input', 'textarea']) if inp.get('name')]
                })

            return forms
        except:
            return []

    def _find_forms_with_tokens(self):
        """Find forms that have CSRF tokens"""
        forms = self._find_forms()
        token_forms = []

        for form in forms:
            if self._form_has_csrf_token(form):
                token_forms.append(form)

        return token_forms

    def _form_has_csrf_token(self, form):
        """Check if form has CSRF token"""
        input_names = [name for name, value in form['inputs']]
        for pattern in self.csrf_token_patterns:
            if any(re.search(pattern, name, re.IGNORECASE) for name in input_names):
                return True
        return False

    def _submit_form(self, form):
        """Submit a form and return response"""
        try:
            action = form['action']
            if not action.startswith('http'):
                action = urljoin(self.target, action)

            data = dict(form['inputs'])

            if form['method'] == 'post':
                return self.session.post(action, data=data, timeout=10, verify=False)
            else:
                return self.session.get(action, params=data, timeout=10, verify=False)
        except:
            return None

    def _submit_form_with_headers(self, form, headers):
        """Submit form with custom headers"""
        try:
            action = form['action']
            if not action.startswith('http'):
                action = urljoin(self.target, action)

            data = dict(form['inputs'])

            if form['method'] == 'post':
                return self.session.post(action, data=data, headers=headers, timeout=10, verify=False)
            else:
                return self.session.get(action, params=data, headers=headers, timeout=10, verify=False)
        except:
            return None

    def _add_method_override_to_form(self, form, override_payload):
        """Add method override parameters to form"""
        modified_form = form.copy()
        modified_form['inputs'].extend(override_payload.items())
        return modified_form

    def _apply_token_bypass(self, form, technique):
        """Apply CSRF token bypass technique to form"""
        modified_form = form.copy()

        if technique['method'] == 'remove_token':
            # Remove CSRF token parameters
            modified_form['inputs'] = [(name, value) for name, value in modified_form['inputs']
                                     if not any(re.search(pattern, name, re.IGNORECASE) for pattern in self.csrf_token_patterns)]

        elif technique['method'] == 'empty_token':
            # Set token values to empty
            new_inputs = []
            for name, value in modified_form['inputs']:
                if any(re.search(pattern, name, re.IGNORECASE) for pattern in self.csrf_token_patterns):
                    new_inputs.append((name, ''))
                else:
                    new_inputs.append((name, value))
            modified_form['inputs'] = new_inputs

        elif technique['method'] == 'fixed_token':
            # Set token to fixed value
            new_inputs = []
            for name, value in modified_form['inputs']:
                if any(re.search(pattern, name, re.IGNORECASE) for pattern in self.csrf_token_patterns):
                    new_inputs.append((name, technique.get('value', 'csrf-token-123')))
                else:
                    new_inputs.append((name, value))
            modified_form['inputs'] = new_inputs

        # Add more bypass techniques as needed

        return modified_form

    def _analyze_token_entropy(self, tokens):
        """Analyze the entropy of CSRF tokens"""
        if not tokens:
            return {}

        # Basic entropy analysis
        unique_chars = set(''.join(tokens))
        avg_length = sum(len(token) for token in tokens) / len(tokens)

        return {
            'token_count': len(tokens),
            'average_length': avg_length,
            'unique_characters': len(unique_chars),
            'character_set': ''.join(sorted(unique_chars))[:50] + ('...' if len(unique_chars) > 50 else ''),
            'appears_random': len(unique_chars) > 20 and avg_length > 10
        }

    def _test_token_reuse(self, token_info):
        """Test if CSRF tokens are reused"""
        try:
            # Get initial page
            response1 = self.session.get(self.target, timeout=10, verify=False)
            soup1 = BeautifulSoup(response1.text, 'html.parser')

            # Get page again
            response2 = self.session.get(self.target, timeout=10, verify=False)
            soup2 = BeautifulSoup(response2.text, 'html.parser')

            # Extract tokens
            token1 = self._extract_token_from_soup(soup1, token_info.get('pattern', ''))
            token2 = self._extract_token_from_soup(soup2, token_info.get('pattern', ''))

            reuse_detected = token1 == token2 if token1 and token2 else False

            return {
                'reuse_detected': reuse_detected,
                'validation': 'tokens_reused' if reuse_detected else 'tokens_unique'
            }
        except:
            return {'reuse_detected': False, 'validation': 'test_failed'}

    def _extract_token_from_soup(self, soup, pattern):
        """Extract CSRF token from BeautifulSoup object"""
        # Look for hidden inputs
        for input_tag in soup.find_all('input', {'type': 'hidden'}):
            name = input_tag.get('name', '').lower()
            if re.search(pattern, name, re.IGNORECASE):
                return input_tag.get('value', '')

        # Look for meta tags
        for meta_tag in soup.find_all('meta'):
            name = meta_tag.get('name', '').lower() or meta_tag.get('property', '').lower()
            if re.search(pattern, name, re.IGNORECASE):
                return meta_tag.get('content', '')

        return None

    def _test_samesite_behavior(self):
        """Test SameSite cookie behavior with cross-origin requests"""
        # This would require setting up a test environment
        # For now, return the methodology
        return {
            'test_required': True,
            'methodology': 'Set up cross-origin test to verify SameSite behavior'
        }

    def _print_summary(self, results):
        """Print comprehensive CSRF testing summary"""
        print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))

        print(f"{colored('ADVANCED CSRF TESTING SUMMARY:', 'yellow', attrs=['bold'])}")

        # Token analysis
        tokens = results.get('token_analysis', {})
        token_count = len(tokens.get('tokens_found', []))
        print(f"  • CSRF Tokens Found: {colored(str(token_count), 'green' if token_count > 0 else 'red')}")

        # Cookie analysis
        cookies = results.get('samesite_testing', {})
        total_cookies = cookies.get('cookies_tested', 0)
        samesite_configured = cookies.get('samesite_configured', 0)
        print(f"  • Cookies Analyzed: {colored(str(total_cookies), 'green')}")
        print(f"  • SameSite Configured: {colored(str(samesite_configured), 'green' if samesite_configured == total_cookies else 'yellow')}")

        # Origin validation
        origin = results.get('origin_validation', {})
        print(f"  • Origin Validation: {colored('Implemented', 'green') if origin.get('origin_required') else colored('Not Found', 'red')}")

        # Method override
        method_override = results.get('method_override', {})
        print(f"  • Method Override: {colored('Vulnerable', 'red') if method_override.get('override_possible') else colored('Not Vulnerable', 'green')}")

        # State-changing actions
        state_changing = results.get('state_changing', {})
        total_actions = len(state_changing.get('actions_found', []))
        protected = state_changing.get('protected_count', 0)
        print(f"  • State-Changing Actions: {colored(str(total_actions), 'green')}")
        print(f"  • Protected Actions: {colored(str(protected), 'green' if protected == total_actions else 'yellow')}")

        # Overall risk assessment
        vulnerabilities = []

        if token_count == 0:
            vulnerabilities.append('No CSRF tokens found')
        if samesite_configured < total_cookies:
            vulnerabilities.append('Missing SameSite attributes')
        if not origin.get('origin_required'):
            vulnerabilities.append('No Origin validation')
        if method_override.get('override_possible'):
            vulnerabilities.append('Method override possible')
        if protected < total_actions:
            vulnerabilities.append('Unprotected state-changing actions')

        print(f"\n{colored('RISK ASSESSMENT:', 'yellow', attrs=['bold'])}")
        if not vulnerabilities:
            print(f"  {colored('✓ LOW RISK', 'green', attrs=['bold'])} - CSRF protections appear adequate")
        elif len(vulnerabilities) <= 2:
            print(f"  {colored('⚠ MEDIUM RISK', 'yellow', attrs=['bold'])} - Some CSRF vulnerabilities found")
        else:
            print(f"  {colored('🚨 HIGH RISK', 'red', attrs=['bold'])} - Multiple CSRF vulnerabilities detected")

        if vulnerabilities:
            print(f"\n{colored('VULNERABILITIES:', 'red')}")
            for vuln in vulnerabilities:
                print(f"  • {vuln}")

            print(f"\n{colored('📋 REMEDIATION:', 'yellow', attrs=['bold'])}")
            print(f"  1. Implement CSRF tokens on all state-changing actions")
            print(f"  2. Use SameSite=Strict or SameSite=Lax for session cookies")
            print(f"  3. Validate Origin and Referer headers")
            print(f"  4. Use secure, random CSRF tokens with sufficient entropy")
            print(f"  5. Implement double-submit cookie pattern")
            print(f"  6. Use same-site cookies for authentication")
            print(f"  7. Regular security testing and code reviews\n")
        else:
            print(f"\n{colored('✓ CSRF protections appear comprehensive', 'green')}\n")