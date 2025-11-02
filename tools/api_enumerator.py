"""Enhanced API Enumeration Module

Replaces basic apiscan with comprehensive API discovery and enumeration.
Includes path enumeration, HTTP method enumeration, parameter discovery,
endpoint linking, documentation discovery, sub-API discovery, API versioning
detection, CORS misconfiguration testing, authentication bypass, and rate
limiting analysis.
"""

import requests
import json
import sys
import os
import time
import re
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.color_compat import colored
from utils.ascii_art import AsciiArt


class APIEnumerator:
    """Enhanced API enumeration and discovery suite"""

    def __init__(self, target):
        self.target = target if target.startswith('http') else f'http://{target}'
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberGuardian/2.0',
            'Accept': 'application/json, text/plain, */*'
        })

        # API paths and endpoints
        self.api_paths = [
            # Version-based paths
            '/api', '/api/v1', '/api/v2', '/api/v3', '/api/v4',
            '/api/v1.0', '/api/v1.1', '/api/v1.2', '/api/v2.0',
            '/rest', '/rest/v1', '/rest/v2',
            '/v1', '/v2', '/v3', '/v4',
            '/graphql', '/api/graphql', '/graphql/v1', '/v1/graphql',

            # Common API endpoints
            '/api/users', '/api/auth', '/api/login', '/api/register',
            '/api/data', '/api/admin', '/api/config', '/api/settings',
            '/api/webhook', '/api/callback', '/api/upload', '/api/download',
            '/api/search', '/api/query', '/api/fetch', '/api/proxy',
            '/api/orders', '/api/products', '/api/customers', '/api/payments',
            '/api/analytics', '/api/logs', '/api/status', '/api/health',

            # Documentation endpoints
            '/docs', '/api-docs', '/swagger', '/swagger-ui',
            '/swagger.json', '/openapi.json', '/api/swagger', '/api/openapi',
            '/redoc', '/redoc.json', '/api/redoc',
            '/postman', '/api/postman', '/collection.json',

            # Alternative API paths
            '/service', '/services', '/backend', '/internal',
            '/gateway', '/proxy', '/endpoint', '/endpoints',
            '/app', '/application', '/system', '/core'
        ]

        # HTTP methods to test
        self.http_methods = [
            'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT', 'PROPFIND'
        ]

        # Common API parameters
        self.common_params = [
            'id', 'user_id', 'session_id', 'token', 'key', 'api_key',
            'format', 'callback', 'json', 'xml', 'debug', 'test',
            'limit', 'offset', 'page', 'size', 'count', 'sort',
            'order', 'filter', 'search', 'query', 'q', 'fields',
            'version', 'lang', 'locale', 'timezone', 'currency'
        ]

        # Documentation patterns
        self.doc_patterns = [
            'swagger', 'openapi', 'redoc', 'apiary', 'raml',
            'wadl', 'postman', 'insomnia', 'api-docs', 'documentation'
        ]

    def enumerate_api(self):
        """Main API enumeration function"""
        print(colored("\n╔═══════════════════ ADVANCED API ENUMERATION ════════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        try:
            results = {
                'paths': self._discover_api_paths(),
                'methods': self._enumerate_http_methods(),
                'documentation': self._find_documentation(),
                'parameters': self._discover_parameters(),
                'versioning': self._detect_api_versioning(),
                'cors': self._test_cors_misconfiguration(),
                'auth_bypass': self._test_authentication_bypass(),
                'rate_limiting': self._analyze_rate_limiting(),
                'sub_apis': self._discover_sub_apis(),
                'endpoint_linking': self._analyze_endpoint_linking()
            }

            self._print_summary(results)
            return results

        except Exception as e:
            AsciiArt.error_message(f"API enumeration failed: {str(e)}")
            return {}

    def _discover_api_paths(self):
        """Discover API paths and endpoints"""
        print(f"{colored('Discovering API paths...', 'yellow')}")

        discovered = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_path = {
                executor.submit(self._test_api_path, path): path
                for path in self.api_paths
            }

            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result['discovered']:
                        discovered.append(result)
                        status_color = 'green' if result['status'] == 200 else 'yellow'
                        print(f"  {colored('✓', 'green')} {path} [{colored(result['status'], status_color)}] ({result['auth']})")
                except:
                    continue

        if not discovered:
            print(f"  {colored('ℹ No API paths discovered', 'blue')}")

        return discovered

    def _enumerate_http_methods(self):
        """Enumerate supported HTTP methods on discovered endpoints"""
        print(f"\n{colored('Enumerating HTTP methods...', 'yellow')}")

        method_results = []

        # Test a few discovered endpoints
        test_endpoints = ['/api', '/api/v1', '/graphql']

        for endpoint in test_endpoints:
            url = f"{self.target.rstrip('/')}{endpoint}"
            print(f"  {colored('Testing endpoint:', 'white')} {endpoint}")

            for method in self.http_methods:
                try:
                    response = self.session.request(method, url, timeout=5, verify=False)

                    if response.status_code not in [404, 405, 501]:
                        method_results.append({
                            'endpoint': endpoint,
                            'method': method,
                            'status': response.status_code,
                            'content_type': response.headers.get('content-type', ''),
                            'length': len(response.text)
                        })

                        if method not in ['GET', 'POST', 'OPTIONS']:
                            print(f"    {colored('✗', 'red')} {method} [{colored(response.status_code, 'yellow')}]")

                except:
                    continue

        if not method_results:
            print(f"  {colored('ℹ No additional HTTP methods discovered', 'blue')}")

        return method_results

    def _find_documentation(self):
        """Find API documentation endpoints"""
        print(f"\n{colored('Finding API documentation...', 'yellow')}")

        documentation = []

        doc_paths = [
            '/docs', '/api-docs', '/swagger', '/swagger-ui',
            '/swagger.json', '/openapi.json', '/redoc',
            '/postman', '/api/spec', '/api/schema'
        ]

        for path in doc_paths:
            try:
                url = f"{self.target.rstrip('/')}{path}"
                response = self.session.get(url, timeout=10, verify=False)

                if response.status_code == 200:
                    # Check if it's actually API documentation
                    content = response.text.lower()
                    if any(pattern in content for pattern in self.doc_patterns):
                        documentation.append({
                            'path': path,
                            'status': response.status_code,
                            'type': self._detect_doc_type(content),
                            'size': len(response.text)
                        })
                        print(f"  {colored('✓', 'green')} {path} [{colored(response.status_code, 'green')}] ({self._detect_doc_type(content)})")

            except:
                continue

        if not documentation:
            print(f"  {colored('ℹ No API documentation found', 'blue')}")

        return documentation

    def _discover_parameters(self):
        """Discover API parameters through fuzzing"""
        print(f"\n{colored('Discovering API parameters...', 'yellow')}")

        discovered_params = []

        # Test GET parameter fuzzing on common endpoints
        test_endpoints = ['/api', '/api/v1', '/api/users', '/api/data']

        for endpoint in test_endpoints[:2]:  # Limit to avoid too many requests
            url = f"{self.target.rstrip('/')}{endpoint}"
            print(f"  {colored('Fuzzing endpoint:', 'white')} {endpoint}")

            for param in self.common_params[:10]:  # Test first 10 parameters
                try:
                    test_params = {param: 'test'}
                    response_without = self.session.get(url, timeout=5, verify=False)
                    response_with = self.session.get(url, params=test_params, timeout=5, verify=False)

                    # Check if parameter has an effect
                    if (response_with.status_code != response_without.status_code or
                        len(response_with.text) != len(response_without.text)):

                        discovered_params.append({
                            'endpoint': endpoint,
                            'parameter': param,
                            'effect': True
                        })

                        print(f"    {colored('✓', 'green')} Parameter {param} affects response")

                except:
                    continue

        if not discovered_params:
            print(f"  {colored('ℹ No interesting parameters discovered', 'blue')}")

        return discovered_params

    def _detect_api_versioning(self):
        """Detect API versioning schemes"""
        print(f"\n{colored('Detecting API versioning...', 'yellow')}")

        versioning = {
            'schemes': [],
            'versions': [],
            'latest': None
        }

        # Test different versioning patterns
        version_tests = [
            ('Path-based', ['/api/v1', '/api/v2', '/api/v3']),
            ('Header-based', [('GET', '/api', {'Accept': 'application/vnd.api+json;version=1'})]),
            ('Parameter-based', [('GET', '/api', {'version': '1'})]),
            ('Subdomain-based', ['v1.api', 'v2.api', 'api-v1'])
        ]

        for scheme, tests in version_tests:
            if scheme == 'Path-based':
                versions_found = []
                for version_path in tests:
                    try:
                        url = f"{self.target.rstrip('/')}{version_path}"
                        response = self.session.get(url, timeout=5, verify=False)
                        if response.status_code == 200:
                            versions_found.append(version_path.split('/')[-1])
                    except:
                        continue

                if versions_found:
                    versioning['schemes'].append(scheme)
                    versioning['versions'].extend(versions_found)
                    print(f"  {colored('✓', 'green')} {scheme}: {', '.join(versions_found)}")

            elif scheme == 'Subdomain-based':
                # Test subdomain versioning (would require DNS setup)
                print(f"  {colored('ℹ', 'blue')} {scheme}: Requires DNS configuration")

            else:
                # Test header and parameter versioning
                for method, path, headers_or_params in tests:
                    try:
                        url = f"{self.target.rstrip('/')}{path}"
                        if scheme == 'Header-based':
                            response = self.session.request(method, url, headers=headers_or_params, timeout=5, verify=False)
                        else:
                            response = self.session.request(method, url, params=headers_or_params, timeout=5, verify=False)

                        if response.status_code == 200:
                            versioning['schemes'].append(scheme)
                            print(f"  {colored('✓', 'green')} {scheme}: Supported")
                            break
                    except:
                        continue

        if not versioning['schemes']:
            print(f"  {colored('ℹ No API versioning detected', 'blue')}")

        return versioning

    def _test_cors_misconfiguration(self):
        """Test for CORS misconfigurations"""
        print(f"\n{colored('Testing CORS configuration...', 'yellow')}")

        cors_results = {
            'misconfigured': False,
            'origins': [],
            'methods': [],
            'headers': []
        }

        # Test with various origins
        test_origins = [
            'http://evil.com',
            'https://evil.com',
            'http://localhost:3000',
            'null',
            '*'
        ]

        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(self.target, headers=headers, timeout=5, verify=False)

                acao = response.headers.get('Access-Control-Allow-Origin')
                acac = response.headers.get('Access-Control-Allow-Credentials')
                acam = response.headers.get('Access-Control-Allow-Methods')

                if acao:
                    cors_results['origins'].append({
                        'origin': origin,
                        'allowed': acao,
                        'credentials': acac
                    })

                    # Check for dangerous CORS configurations
                    if (acao == '*' and acac == 'true') or acao == origin:
                        cors_results['misconfigured'] = True
                        print(f"  {colored('✗', 'red')} Dangerous CORS: Origin {origin} -> {acao}")

            except:
                continue

        # Test preflight requests
        try:
            headers = {
                'Origin': 'http://evil.com',
                'Access-Control-Request-Method': 'PUT',
                'Access-Control-Request-Headers': 'Authorization'
            }
            response = self.session.options(self.target, headers=headers, timeout=5, verify=False)
            acam = response.headers.get('Access-Control-Allow-Methods')
            if acam:
                cors_results['methods'] = acam.split(', ')
        except:
            pass

        if not cors_results['misconfigured'] and not cors_results['origins']:
            print(f"  {colored('✓', 'green')} CORS appears properly configured")
        elif not cors_results['misconfigured']:
            print(f"  {colored('⚠', 'yellow')} CORS detected but appears safe")

        return cors_results

    def _test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        print(f"\n{colored('Testing authentication bypass...', 'yellow')}")

        auth_results = {
            'bypass_found': False,
            'methods': []
        }

        # Test endpoints without authentication
        protected_endpoints = ['/api/admin', '/api/users', '/api/config', '/api/data']

        for endpoint in protected_endpoints:
            url = f"{self.target.rstrip('/')}{endpoint}"
            try:
                # Test without any auth headers
                response = self.session.get(url, timeout=5, verify=False)

                if response.status_code == 200:
                    auth_results['bypass_found'] = True
                    auth_results['methods'].append({
                        'endpoint': endpoint,
                        'method': 'No Authentication',
                        'status': response.status_code
                    })
                    print(f"  {colored('✗', 'red')} No auth required for {endpoint}")

                # Test with common bypass headers
                bypass_headers = [
                    {'X-Forwarded-For': '127.0.0.1'},
                    {'X-Real-IP': '127.0.0.1'},
                    {'X-Original-URL': '/admin'},
                    {'X-Rewrite-URL': '/admin'},
                ]

                for headers in bypass_headers:
                    response = self.session.get(url, headers=headers, timeout=5, verify=False)
                    if response.status_code == 200:
                        auth_results['bypass_found'] = True
                        auth_results['methods'].append({
                            'endpoint': endpoint,
                            'method': f"Header bypass: {list(headers.keys())[0]}",
                            'status': response.status_code
                        })
                        print(f"  {colored('✗', 'red')} Header bypass for {endpoint}: {list(headers.keys())[0]}")

            except:
                continue

        if not auth_results['bypass_found']:
            print(f"  {colored('✓', 'green')} No obvious authentication bypass found")

        return auth_results

    def _analyze_rate_limiting(self):
        """Analyze API rate limiting mechanisms"""
        print(f"\n{colored('Analyzing rate limiting...', 'yellow')}")

        rate_limit_results = {
            'limited': False,
            'method': None,
            'threshold': None
        }

        test_url = f"{self.target.rstrip('/')}/api"
        request_count = 0
        limit_detected = False

        try:
            # Make rapid requests to test rate limiting
            for i in range(20):  # Test 20 rapid requests
                start_time = time.time()
                response = self.session.get(test_url, timeout=5, verify=False)
                end_time = time.time()
                request_count += 1

                # Check for rate limiting indicators
                if (response.status_code in [429, 503] or
                    'rate-limit' in response.headers.get('x-ratelimit-remaining', '').lower() or
                    'rate' in response.text.lower()):

                    rate_limit_results['limited'] = True
                    rate_limit_results['threshold'] = request_count
                    limit_detected = True

                    # Try to identify the rate limiting method
                    if response.status_code == 429:
                        rate_limit_results['method'] = 'HTTP 429'
                    elif 'x-ratelimit' in str(response.headers).lower():
                        rate_limit_results['method'] = 'Rate Limit Headers'
                    elif 'retry-after' in response.headers:
                        rate_limit_results['method'] = 'Retry-After Header'
                    else:
                        rate_limit_results['method'] = 'Unknown'

                    print(f"  {colored('✓', 'green')} Rate limiting detected after {request_count} requests")
                    print(f"    Method: {colored(rate_limit_results['method'], 'yellow')}")
                    break

                # Add small delay to avoid overwhelming the server
                time.sleep(0.1)

        except:
            pass

        if not limit_detected:
            print(f"  {colored('⚠', 'yellow')} No rate limiting detected (or very high limits)")

        return rate_limit_results

    def _discover_sub_apis(self):
        """Discover sub-APIs and microservices"""
        print(f"\n{colored('Discovering sub-APIs...', 'yellow')}")

        sub_apis = []

        # Common sub-API patterns
        sub_patterns = [
            '/auth', '/login', '/register', '/users', '/admin',
            '/payments', '/orders', '/products', '/inventory',
            '/analytics', '/logs', '/notifications', '/emails',
            '/files', '/images', '/documents', '/media',
            '/search', '/recommendations', '/reviews', '/comments',
            '/webhooks', '/callbacks', '/integrations', '/external'
        ]

        base_url = f"{self.target.rstrip()}/api"

        for pattern in sub_patterns:
            try:
                url = f"{base_url}{pattern}"
                response = self.session.get(url, timeout=5, verify=False)

                if response.status_code in [200, 401, 403]:  # 401/403 indicate valid endpoint
                    sub_apis.append({
                        'path': f"/api{pattern}",
                        'status': response.status_code,
                        'size': len(response.text),
                        'content_type': response.headers.get('content-type', '')
                    })

                    status_color = 'green' if response.status_code == 200 else 'yellow'
                    print(f"  {colored('✓', 'green')} {pattern} [{colored(response.status_code, status_color)}]")

            except:
                continue

        if not sub_apis:
            print(f"  {colored('ℹ No sub-APIs discovered', 'blue')}")

        return sub_apis

    def _analyze_endpoint_linking(self):
        """Analyze endpoint relationships and HATEOAS"""
        print(f"\n{colored('Analyzing endpoint linking...', 'yellow')}")

        linking_results = {
            'hateoas_found': False,
            'links': []
        }

        try:
            # Check main API endpoints for HATEOAS links
            endpoints_to_check = ['/api', '/api/v1', '/api/users']

            for endpoint in endpoints_to_check:
                url = f"{self.target.rstrip('/')}{endpoint}"
                try:
                    response = self.session.get(url, timeout=5, verify=False)

                    if response.status_code == 200:
                        # Look for HATEOAS patterns
                        content = response.text
                        link_patterns = [
                            r'"_links":\s*\{',  # HAL/HATEOAS
                            r'"href":\s*"[^"]*/api',  # API links
                            r'"rel":\s*"[^"]*".*"href"',  # Link relations
                            r'<link[^>]*rel="[^"]*"[^>]*href="[^"]*"',  # HTML link headers
                        ]

                        for pattern in link_patterns:
                            if re.search(pattern, content):
                                linking_results['hateoas_found'] = True
                                linking_results['links'].append({
                                    'endpoint': endpoint,
                                    'pattern': pattern,
                                    'sample': content[:200] + '...'
                                })
                                print(f"  {colored('✓', 'green')} HATEOAS links found in {endpoint}")
                                break

                except:
                    continue

        except:
            pass

        if not linking_results['hateoas_found']:
            print(f"  {colored('ℹ No HATEOAS or endpoint linking detected', 'blue')}")

        return linking_results

    def _test_api_path(self, path):
        """Test if an API path exists"""
        try:
            url = f"{self.target.rstrip('/')}{path}"
            response = self.session.get(url, timeout=10, verify=False)

            if response.status_code in [200, 401, 403]:  # Valid endpoints
                return {
                    'path': path,
                    'discovered': True,
                    'status': response.status_code,
                    'auth': 'requires auth' if response.status_code in [401, 403] else 'public',
                    'content_type': response.headers.get('content-type', ''),
                    'size': len(response.text)
                }
            elif response.status_code in [301, 302, 307, 308]:  # Redirects
                return {
                    'path': path,
                    'discovered': True,
                    'status': response.status_code,
                    'auth': 'redirect',
                    'location': response.headers.get('location', ''),
                    'content_type': response.headers.get('content-type', ''),
                    'size': len(response.text)
                }

        except:
            pass

        return {'path': path, 'discovered': False, 'status': None, 'auth': None}

    def _detect_doc_type(self, content):
        """Detect the type of API documentation"""
        if 'swagger' in content or 'openapi' in content:
            return 'Swagger/OpenAPI'
        elif 'redoc' in content:
            return 'ReDoc'
        elif 'postman' in content:
            return 'Postman Collection'
        elif 'apiary' in content:
            return 'APIary'
        else:
            return 'Unknown'

    def _print_summary(self, results):
        """Print comprehensive API enumeration summary"""
        print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))

        print(f"{colored('API ENUMERATION SUMMARY:', 'yellow', attrs=['bold'])}")

        # Paths discovered
        paths = results.get('paths', [])
        print(f"  • API Paths Discovered: {colored(str(len(paths)), 'green')}")

        if paths:
            print(f"    Public endpoints: {colored(str(len([p for p in paths if p['auth'] == 'public'])), 'green')}")
            print(f"    Authenticated: {colored(str(len([p for p in paths if p['auth'] == 'requires auth'])), 'yellow')}")
            print(f"    Redirects: {colored(str(len([p for p in paths if p['auth'] == 'redirect'])), 'blue')}")

        # Documentation
        docs = results.get('documentation', [])
        print(f"  • Documentation Found: {colored(str(len(docs)), 'green' if docs else 'white')}")

        # HTTP Methods
        methods = results.get('methods', [])
        if methods:
            unique_methods = list(set(m['method'] for m in methods))
            print(f"  • HTTP Methods Supported: {colored(', '.join(unique_methods), 'green')}")

        # Security Issues
        security_issues = []

        cors = results.get('cors', {})
        if cors.get('misconfigured'):
            security_issues.append('CORS Misconfiguration')

        auth = results.get('auth_bypass', {})
        if auth.get('bypass_found'):
            security_issues.append('Authentication Bypass')

        rate_limit = results.get('rate_limiting', {})
        if not rate_limit.get('limited'):
            security_issues.append('No Rate Limiting')

        print(f"  • Security Issues Found: {colored(str(len(security_issues)), 'red' if security_issues else 'green')}")

        if security_issues:
            print(f"    {', '.join(security_issues)}")

        print(f"\n{colored('DETAILED FINDINGS:', 'yellow', attrs=['bold'])}")

        # Print discovered endpoints
        if paths:
            print(f"\n{colored('API Endpoints:', 'green')}")
            for path in paths[:10]:  # Show first 10
                status_color = 'green' if path['status'] == 200 else 'yellow' if path['status'] in [401, 403] else 'white'
                print(f"  • {path['path']} [{colored(path['status'], status_color)}] ({path['auth']})")
            if len(paths) > 10:
                print(f"    ... and {len(paths) - 10} more")

        # Print documentation
        if docs:
            print(f"\n{colored('Documentation:', 'green')}")
            for doc in docs:
                print(f"  • {doc['path']} [{colored(doc['status'], 'green')}] ({doc['type']})")

        # Print security recommendations
        if security_issues:
            print(f"\n{colored('🔒 SECURITY RECOMMENDATIONS:', 'yellow', attrs=['bold'])}")
            if 'CORS Misconfiguration' in security_issues:
                print(f"  • Fix CORS configuration to avoid cross-origin attacks")
            if 'Authentication Bypass' in security_issues:
                print(f"  • Implement proper authentication on all API endpoints")
            if 'No Rate Limiting' in security_issues:
                print(f"  • Implement rate limiting to prevent abuse")
            print(f"  • Use API keys and OAuth for proper access control")
            print(f"  • Implement request validation and input sanitization")
            print(f"  • Monitor API usage for suspicious patterns")
            print(f"  • Use HTTPS for all API communications\n")
        else:
            print(f"\n{colored('✓ API appears to have basic security measures in place', 'green')}\n")