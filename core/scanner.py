"""Core scanning engine"""

import sys
import json
import time
import datetime
import threading
import concurrent.futures
import nmap
import requests
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from html import escape

from config import CONFIG
from utils.printer import Printer
from utils.progress import ScanProgress
from utils.resolver import TargetResolver
from .vulnerability import ThreatIntel


class CyberSentinel:
    """Main scanning engine for CyberGuardian Ultimate"""

    def __init__(self):
        self.nm = nmap.PortScanner()
        self.session_id = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        self.findings = {
            'target': None,
            'ips': [],
            'ports': [],
            'vulnerabilities': [],
            'directories': [],
            'exploits': []
        }
        self.progress = ScanProgress()
        self.input_queue = Queue()
        self.scan_active = False

        ThreatIntel.initialize_environment()
        self._load_databases()
        self._start_input_handler()

    def _start_input_handler(self):
        """Start background thread to handle Enter key status checks"""
        def input_listener():
            while True:
                input()
                if self.scan_active:
                    self._check_status(force=True)
        threading.Thread(target=input_listener, daemon=True).start()

    def _check_status(self, force=False):
        """Display current scan progress"""
        progress = self.progress.get_progress()
        status_msg = (
            f"Progress [Ports: {progress['ports']} | "
            f"Dirs: {progress['directories']} | "
            f"Elapsed: {progress['elapsed']}]"
        )

        sys.stdout.write('\033[2K\033[1G')
        sys.stdout.write(status_msg + '\n')
        sys.stdout.flush()

    def _load_databases(self):
        """Load CVE database and wordlists"""
        try:
            # Load JSON with mixed encoding support
            with open('data/cve_db.json', 'r', encoding='utf-8') as f:
                self.cve_db = json.load(f)

            # Load directories with UTF-8 and fallback to latin-1
            try:
                with open('data/directories.txt', 'r', encoding='utf-8') as f:
                    self.common_dirs = f.read().splitlines()
            except UnicodeDecodeError:
                with open('data/directories.txt', 'r', encoding='latin-1') as f:
                    self.common_dirs = f.read().splitlines()

        except Exception as e:
            Printer.error(f"Database load failed: {str(e)}")
            sys.exit(1)

    def scan_target(self, target, mode='fast'):
        """
        Main scan orchestration method.

        Args:
            target: Target IP, domain, or URL
            mode: 'fast' (ports 1-1000) or 'deep' (ports 1-65535)
        """
        self.findings['target'] = target
        resolved_ips = TargetResolver.resolve_target(target)

        if not resolved_ips:
            Printer.error("Scan aborted - invalid target")
            return

        self.findings['ips'] = resolved_ips

        for ip in resolved_ips:
            Printer.status(f"Scanning {ip}")
            self.port_scan(ip, '1-1000' if mode == 'fast' else '1-65535')
            self.vulnerability_assessment(ip)

        if target.startswith('http'):
            self.directory_enum(target)

    def port_scan(self, ip, ports):
        """Perform port scan with improved progress tracking"""
        try:
            self.scan_active = True
            Printer.status(f"Starting port scan on {ip} ({ports})")

            # Calculate estimated port count
            if '-' in ports:
                port_parts = ports.split('-')
                estimated_ports = int(port_parts[1]) - int(port_parts[0]) + 1
            else:
                estimated_ports = len(ports.split(','))

            # Configure scan parameters
            scan_args = '-sS -sV -T4 --open --script vulners'
            self.nm.scan(ip, ports, arguments=scan_args)

            # Track scan progress with better estimation
            start_time = time.time()
            last_update = 0
            while self.nm.still_scanning():
                elapsed = time.time() - start_time
                # Improved progress estimation based on typical scan speeds
                progress = min(int((elapsed / (estimated_ports * 0.01)) * 100), 99)
                self.progress.update_ports(progress, 100)

                if elapsed - last_update >= 1:
                    self._check_status()
                    last_update = elapsed
                time.sleep(0.5)

            # Mark as complete
            self.progress.update_ports(100, 100)

            # Process results with better error handling
            if ip not in self.nm.all_hosts():
                Printer.warning(f"No open ports found on {ip} or target is unreachable")
                return

            host_data = self.nm[ip]
            open_ports = []

            for proto in host_data.all_protocols():
                ports_list = host_data[proto].keys()
                for port in ports_list:
                    service = host_data[proto][port]
                    open_ports.append({
                        'ip': ip,
                        'port': port,
                        'protocol': proto,
                        'service': f"{service['name']} {service.get('product', '')}".strip(),
                        'version': service.get('version', ''),
                        'state': service['state']
                    })

            # Update findings
            self.findings['ports'].extend(open_ports)
            Printer.success(f"Port scan completed for {ip} (Found {len(open_ports)} open ports)")

        except Exception as e:
            Printer.error(f"Port scan failed: {str(e)}")
        finally:
            self.scan_active = False

    def vulnerability_assessment(self, ip):
        """Correlate discovered services with CVE database and Exploit-DB"""
        try:
            for service in self.findings['ports']:
                if service['ip'] != ip:
                    continue

                base_service = service['service'].split()[0].lower()
                if base_service in self.cve_db:
                    for vuln in self.cve_db[base_service]:
                        self._add_vulnerability(service, vuln)

                exploits = self._check_exploit_db(service)
                for exploit in exploits:
                    self.findings['exploits'].append({
                        'service': service['service'],
                        'exploit_id': exploit['id'],
                        'description': exploit['description'],
                        'url': f"https://www.exploit-db.com/exploits/{exploit['id']}"
                    })
        except Exception as e:
            Printer.error(f"Vulnerability check failed: {str(e)}")

    def _add_vulnerability(self, service, vuln):
        """Add vulnerability finding"""
        self.findings['vulnerabilities'].append({
            'ip': service['ip'],
            'port': service['port'],
            'cve': vuln['cve'],
            'severity': vuln['severity'],
            'description': vuln['description'],
            'service': service['service']
        })
        Printer.critical(f"Found {vuln['cve']} ({vuln['severity']}) - {service['service']}")

    def _check_exploit_db(self, service):
        """
        Search Exploit-DB for available exploits using local CSV database.
        Falls back to web scraping if CSV is unavailable.
        """
        service_name = service['service'].split()[0]
        service_version = service.get('version', '')

        # Try local CSV search first (faster and more reliable)
        exploits = ThreatIntel.search_exploit_db_csv(service_name, service_version, max_results=3)

        if exploits:
            return exploits

        # Fallback to web scraping if CSV search yielded no results
        try:
            time.sleep(1)  # Respect rate limits
            headers = {
                'User-Agent': CONFIG['user_agent'],
                'Accept-Language': 'en-US,en;q=0.5'
            }

            search_query = f"{service['service']} {service_version}".strip()
            params = {'q': search_query}

            response = requests.get(
                'https://www.exploit-db.com/search',
                params=params,
                headers=headers,
                timeout=15
            )

            if response.status_code != 200:
                return []

            soup = BeautifulSoup(response.text, 'html.parser')
            exploits = []

            for row in soup.select('table.table-exploits tr'):
                cols = row.select('td')
                if len(cols) >= 5:
                    try:
                        exploit_id_elem = cols[1].find('a')
                        description_elem = cols[3] if len(cols) > 3 else None
                        if not exploit_id_elem or not description_elem:
                            continue

                        exploit_id = exploit_id_elem.text.strip()
                        description = description_elem.text.strip()
                        url = f"https://www.exploit-db.com{exploit_id_elem['href']}"
                        exploits.append({
                            'id': exploit_id,
                            'description': description,
                            'url': url
                        })
                    except Exception as e:
                        continue

            return exploits[:3]

        except Exception as e:
            return []

    def directory_enum(self, base_url):
        """Enumerate web directories using wordlist"""
        try:
            self.scan_active = True
            total_dirs = len(self.common_dirs)
            self.progress.update_dirs(0, total_dirs)

            with ThreadPoolExecutor(max_workers=CONFIG['max_threads']) as executor:
                futures = {executor.submit(self._check_dir, base_url, dir): dir
                          for dir in self.common_dirs}

                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            self.findings['directories'].append(result)
                    except Exception as e:
                        Printer.warning(f"Directory check failed: {str(e)}")
                    completed += 1
                    self.progress.update_dirs(completed, total_dirs)
                    self._check_status()

            Printer.success(f"Found {len(self.findings['directories'])} valid directories")
        except Exception as e:
            Printer.error(f"Directory enumeration failed: {str(e)}")
        finally:
            self.scan_active = False

    def _check_dir(self, base_url, directory):
        """Check if a directory exists"""
        try:
            url = f"{base_url.rstrip('/')}/{directory.lstrip('/')}"
            response = requests.get(url, timeout=3, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                return {'url': url, 'status': response.status_code}
        except requests.RequestException:
            # Catch HTTP errors but allow KeyboardInterrupt to propagate
            return None
        except Exception as e:
            # Log unexpected errors but allow keyboard interrupts
            if not isinstance(e, KeyboardInterrupt):
                return None
            raise

    def generate_report(self, format='html'):
        """Generate scan report in specified format"""
        try:
            report_file = f"reports/scan_{self.session_id}.{format}"

            if format == 'html':
                self._generate_html_report(report_file)
            elif format == 'json':
                with open(report_file, 'w') as f:
                    json.dump(self.findings, f, indent=2)

            Printer.success(f"Report generated: {report_file}")
            return report_file

        except Exception as e:
            Printer.error(f"Report generation failed: {str(e)}")
            return None

    def _generate_html_report(self, filename):
        """Generate HTML report with XSS protection"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"""
            <html>
                <head>
                    <title>CyberGuardian Report - {escape(self.findings['target'])}</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; padding: 20px; }}
                        .vulnerability {{ color: #dc3545; font-weight: bold; }}
                        .exploit {{ color: #ff6a00; }}
                        .ip {{ color: #0d6efd; }}
                        a {{ color: #0d6efd; text-decoration: none; }}
                        a:hover {{ text-decoration: underline; }}
                        ul {{ list-style-type: none; padding-left: 20px; }}
                        li {{ margin-bottom: 10px; }}
                    </style>
                </head>
                <body>
                    <h1>Security Report for {escape(self.findings['target'])}</h1>
                    <h3>Scan ID: {escape(self.session_id)}</h3>

                    <h2>Network Discovery</h2>
                    <h3>Resolved IP Addresses</h3>
                    <ul>
                        {"".join(f"<li class='ip'>{escape(ip)}</li>" for ip in self.findings['ips'])}
                    </ul>

                    <h3>Open Ports & Services</h3>
                    <ul>
                        {"".join(
                            f"<li><b>{escape(service['ip'])}:{escape(str(service['port']))}</b> - {escape(service['service'])} "
                            f"(v{escape(service['version'])})</li>"
                            for service in self.findings['ports']
                        )}
                    </ul>

                    <h2>Security Findings</h2>
                    <h3>Vulnerabilities ({len(self.findings['vulnerabilities'])})</h3>
                    <ul>
                        {"".join(
                            f"<li class='vulnerability'>{escape(vuln['cve'])} ({escape(vuln['severity'])})<br>"
                            f"<small>{escape(vuln['description'])}</small><br>"
                            f"<i>Affected service: {escape(vuln['service'])} on {escape(vuln['ip'])}:{escape(str(vuln['port']))}</i></li>"
                            for vuln in self.findings['vulnerabilities']
                        )}
                    </ul>

                    <h3>Potential Exploits ({len(self.findings['exploits'])})</h3>
                    <ul>
                        {"".join(
                            f"<li class='exploit'><a href='{escape(exploit['url'])}' target='_blank'>"
                            f"Exploit {escape(exploit['exploit_id'])}</a>: {escape(exploit['description'])}<br>"
                            f"<i>Target service: {escape(exploit['service'])}</i></li>"
                            for exploit in self.findings['exploits']
                        )}
                    </ul>

                    <h2>Web Directory Discovery ({len(self.findings['directories'])})</h2>
                    <ul>
                        {"".join(
                            f"<li><a href='{escape(dir['url'])}' target='_blank'>{escape(dir['url'])}</a> "
                            f"(HTTP {escape(str(dir['status']))})</li>"
                            for dir in self.findings['directories']
                        )}
                    </ul>
                </body>
            </html>
            """)
