#!/usr/bin/env python3
import argparse
import socket
import json
import requests
import nmap
import os
import datetime
import sys
import shutil
import threading
import time
import subprocess
import webbrowser
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from termcolor import colored
import xml.etree.ElementTree as ET
from pathlib import Path

# Configuration
CONFIG = {
    'cve_db_url': 'https://cve.mitre.org/data/downloads/allitems.csv',
    'dir_list_url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt',
    'exploit_db_api': 'https://exploit-db.com/search',
    'github_repo': 'https://github.com/NikolisSecurity/CyberToolX.git',
    'update_check_interval': 3600,
    'banner_color': 'cyan',
    'highlight_color': 'yellow',
    'critical_color': 'red',
    'max_threads': 50
}

class SecurityArt:
    @staticmethod
    def banner():
        return f"""
        {colored('''
       ██████╗██╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
      ██╔════╝╚██╗ ██╔╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
      ██║      ╚████╔╝ ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
      ██║       ╚██╔╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
      ╚██████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
       ╚═════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                                   
        ''', CONFIG['banner_color'])}
        {colored('CyberGuardian Ultimate v3.0', CONFIG['highlight_color'], attrs=['bold'])}
        {colored('#' * 65, CONFIG['highlight_color'])}
        """

class GitHubUpdater:
    @staticmethod
    def check_update():
        """Check and apply updates from GitHub repository"""
        try:
            if not os.path.exists('.git'):
                Printer.warning("Auto-update disabled (not a git repo)")
                return False

            result = subprocess.run(['git', 'fetch', 'origin'],
                                  capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(result.stderr)

            local_hash = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip()
            remote_hash = subprocess.check_output(['git', 'rev-parse', 'origin/main']).decode().strip()

            if local_hash != remote_hash:
                Printer.success(f"New version available ({remote_hash[:7]})")
                result = subprocess.run(['git', 'pull', '--ff-only', 'origin', 'main'],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    Printer.success("Update successful! Restart required")
                    return True
                else:
                    raise Exception(result.stderr)
            return False
        except Exception as e:
            Printer.error(f"Update failed: {str(e)}")
            return False

class ThreatIntel:
    @staticmethod
    def initialize_environment():
        Path('reports').mkdir(exist_ok=True)
        Path('exploits').mkdir(exist_ok=True)

        required_files = {
            'cve_db.json': CONFIG['cve_db_url'],
            'directories.txt': CONFIG['dir_list_url']
        }

        for filename, url in required_files.items():
            if not Path(filename).exists():
                ThreatIntel.download_resource(url, filename)

    @staticmethod
    def download_resource(url, filename):
        try:
            response = requests.get(url, timeout=10)
            with open(filename, 'wb') as f:
                f.write(response.content)
            Printer.success(f"Downloaded {filename}")
        except Exception as e:
            Printer.error(f"Failed to download {filename}: {str(e)}")
            sys.exit(1)

class Printer:
    @staticmethod
    def _format(message, level, color, attrs=None):
        border = colored('' * (len(message) + 4), color)
        return f"{border}\n  {colored(level, color, attrs=attrs)} {message}\n{border}"

    @staticmethod
    def status(message):
        print(colored(f"[►] {message}", 'blue'))

    @staticmethod
    def success(message):
        print(Printer._format(message, "SUCCESS", 'green'))

    @staticmethod
    def warning(message):
        print(Printer._format(message, "WARNING", 'yellow'))

    @staticmethod
    def error(message):
        print(Printer._format(message, "ERROR", 'red'))

    @staticmethod
    def critical(message):
        print(Printer._format(message, "CRITICAL", 'red', ['bold']))

class ScanProgress:
    def __init__(self):
        self.lock = threading.Lock()
        self.port_total = 0
        self.port_current = 0
        self.dir_total = 0
        self.dir_current = 0
        self.scan_start = time.time()

    def update_ports(self, current, total):
        with self.lock:
            self.port_current = current
            self.port_total = total

    def update_dirs(self, current, total):
        with self.lock:
            self.dir_current = current
            self.dir_total = total

    def get_progress(self):
        with self.lock:
            elapsed = time.time() - self.scan_start
            port_pct = (self.port_current/self.port_total)*100 if self.port_total else 0
            dir_pct = (self.dir_current/self.dir_total)*100 if self.dir_total else 0
            return {
                'ports': f"{port_pct:.1f}%",
                'directories': f"{dir_pct:.1f}%",
                'elapsed': f"{elapsed:.1f}s"
            }

class TargetResolver:
    @staticmethod
    def resolve_target(target):
        try:
            socket.inet_aton(target)
            return [target]
        except socket.error:
            try:
                addr_info = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
                ips = list({ai[4][0] for ai in addr_info})

                if not ips:
                    raise ValueError("No IP addresses found")

                Printer.status(f"Resolved {target} to {len(ips)} IPs:")
                for ip in ips:
                    Printer.info(f"  {ip}")
                return ips
            except Exception as e:
                Printer.error(f"Resolution failed: {str(e)}")
                return None

class CyberSentinel:
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

        ThreatIntel.initialize_environment()
        self._load_databases()
        self._start_input_handler()

        if GitHubUpdater.check_update():
            sys.exit(0)

    def _start_input_handler(self):
        def input_listener():
            while True:
                input()
                self.input_queue.put("status")
        threading.Thread(target=input_listener, daemon=True).start()

    def _check_status(self):
        while not self.input_queue.empty():
            self.input_queue.get()
            progress = self.progress.get_progress()
            Printer.status(
                f"Progress [Ports: {progress['ports']} | "
                f"Dirs: {progress['directories']} | "
                f"Elapsed: {progress['elapsed']}]"
            )

    def _load_databases(self):
        with open('cve_db.json') as f:
            self.cve_db = json.load(f)
        with open('directories.txt') as f:
            self.common_dirs = f.read().splitlines()

    def scan_target(self, target, mode='fast'):
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
        try:
            list_scan = self.nm.scan(ip, arguments='-sL')
            if ip not in list_scan['scan']:
                raise ValueError("Target not in scan results")

            port_list = list_scan['scan'][ip]['tcp'].keys()
            self.progress.update_ports(0, len(port_list))

            scan_result = self.nm.scan(ip, ports, arguments='-sV --script vulners')

            for i, host in enumerate(self.nm.all_hosts()):
                self._check_status()
                for proto in self.nm[host].all_protocols():
                    for port, data in self.nm[host][proto].items():
                        service_info = {
                            'ip': ip,
                            'port': port,
                            'service': f"{data['name']} {data.get('product', '')}",
                            'version': data.get('version', ''),
                            'protocol': proto
                        }
                        self.findings['ports'].append(service_info)
                self.progress.update_ports(i+1, len(port_list))

            Printer.success(f"Port scan completed for {ip}")

        except Exception as e:
            Printer.error(f"Port scan failed: {str(e)}")

    def vulnerability_assessment(self, ip):
        try:
            for service in self.findings['ports']:
                if service['ip'] != ip:
                    continue

                # Check local CVE database
                base_service = service['service'].split()[0].lower()
                if base_service in self.cve_db:
                    for vuln in self.cve_db[base_service]:
                        self._add_vulnerability(service, vuln)

                # Check Exploit-DB
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
        try:
            params = {
                'q': f"{service['service']} {service['version']}",
                'key': os.getenv('EXPLOIT_DB_KEY')
            }
            response = requests.get(CONFIG['exploit_db_api'], params=params, timeout=10)
            return response.json().get('results', [])
        except Exception as e:
            Printer.warning(f"Exploit DB check failed: {str(e)}")
            return []

    def directory_enum(self, base_url):
        try:
            self.progress.update_dirs(0, len(self.common_dirs))

            with ThreadPoolExecutor(max_workers=CONFIG['max_threads']) as executor:
                futures = {executor.submit(self._check_dir, base_url, dir): dir
                          for dir in self.common_dirs}

                for i, future in enumerate(futures):
                    self._check_status()
                    try:
                        result = future.result(timeout=5)
                        if result:
                            self.findings['directories'].append(result)
                        self.progress.update_dirs(i+1, len(self.common_dirs))
                    except:
                        pass

            Printer.success(f"Found {len(self.findings['directories'])} valid directories")

        except Exception as e:
            Printer.error(f"Directory enumeration failed: {str(e)}")

    def _check_dir(self, base_url, directory):
        try:
            url = f"{base_url}/{directory}"
            response = requests.get(url, timeout=3, allow_redirects=False)
            if response.status_code == 200:
                return {'url': url, 'status': response.status_code}
        except:
            return None

    def generate_report(self, format='html'):
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
        with open(filename, 'w') as f:
            f.write(f"""
            <html>
                <head>
                    <title>CyberGuardian Report - {self.findings['target']}</title>
                    <style>
                        body {{ font-family: monospace; padding: 20px; }}
                        .vulnerability {{ color: red; font-weight: bold; }}
                        .exploit {{ color: darkorange; }}
                        .ip {{ color: blue; }}
                    </style>
                </head>
                <body>
                    <h1>Security Report for {self.findings['target']}</h1>
                    <h2>Scan ID: {self.session_id}</h2>

                    <h3>Resolved IP Addresses</h3>
                    <ul>
                        {"".join(f"<li class='ip'>{ip}</li>" for ip in self.findings['ips'])}
                    </ul>

                    <h3>Discovered Services</h3>
                    <ul>
                        {"".join(
                            f"<li>{service['ip']}:{service['port']} - {service['service']}</li>"
                            for service in self.findings['ports']
                        )}
                    </ul>

                    <h3>Vulnerabilities Found</h3>
                    <ul>
                        {"".join(
                            f"<li class='vulnerability'>{vuln['cve']} ({vuln['severity']}): {vuln['description']}</li>"
                            for vuln in self.findings['vulnerabilities']
                        )}
                    </ul>

                    <h3>Potential Exploits</h3>
                    <ul>
                        {"".join(
                            f"<li class='exploit'><a href='{exploit['url']}'>{exploit['exploit_id']}</a>: {exploit['description']}</li>"
                            for exploit in self.findings['exploits']
                        )}
                    </ul>

                    <h3>Discovered Directories</h3>
                    <ul>
                        {"".join(
                            f"<li><a href='{dir['url']}'>{dir['url']}</a> ({dir['status']})</li>"
                            for dir in self.findings['directories']
                        )}
                    </ul>
                </body>
            </html>
            """)

def main():
    print(SecurityArt.banner())
    scanner = CyberSentinel()

    parser = argparse.ArgumentParser(description="CyberGuardian Ultimate - Enterprise Cybersecurity Platform")
    parser.add_argument("target", help="Target IP/URL to scan")
    parser.add_argument("-m", "--mode", choices=['fast', 'deep'], default='fast',
                       help="Scanning intensity level")
    parser.add_argument("-o", "--output", choices=['html', 'json'], default='html',
                       help="Report output format")
    parser.add_argument("-u", "--update", action="store_true",
                       help="Force update check and exit")

    args = parser.parse_args()

    if args.update:
        GitHubUpdater.check_update()
        return

    try:
        scanner.scan_target(args.target, args.mode)
        report_path = scanner.generate_report(args.output)
        if report_path:
            Printer.success(f"Final report: {os.path.abspath(report_path)}")

    except KeyboardInterrupt:
        Printer.error("Scan aborted by user")
        sys.exit(1)
    except Exception as e:
        Printer.error(f"Critical error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
