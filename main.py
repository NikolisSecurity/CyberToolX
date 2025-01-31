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
import csv
import io
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from collections import defaultdict
from termcolor import colored
from pathlib import Path
import xml.etree.ElementTree as ET

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
        {colored('CyberGuardian Ultimate v1.1', CONFIG['highlight_color'], attrs=['bold'])}
        """

class GitHubUpdater:
    @staticmethod
    def check_update():
        """Check and apply updates from GitHub repository with conflict resolution"""
        try:
            if not os.path.exists('.git'):
                Printer.warning("Auto-update disabled (not a git repo)")
                return False

            # Check remote status
            fetch_result = subprocess.run(['git', 'fetch', 'origin'],
                                        capture_output=True, text=True)
            if fetch_result.returncode != 0:
                raise Exception(fetch_result.stderr)

            # Get commit hashes
            local_hash = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip()
            remote_hash = subprocess.check_output(['git', 'rev-parse', 'origin/main']).decode().strip()

            if local_hash == remote_hash:
                return False

            Printer.success(f"New version available ({remote_hash[:7]})")

            # Check for local modifications
            status_result = subprocess.run(['git', 'status', '--porcelain'],
                                         capture_output=True, text=True)
            has_changes = bool(status_result.stdout.strip())

            if has_changes:
                # Create backup of modified files
                backup_dir = f"backup_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
                os.makedirs(backup_dir, exist_ok=True)

                # Copy modified files and directories properly
                for line in status_result.stdout.splitlines():
                    # Extract filename from git status output
                    file_path = line[3:].strip()
                    if os.path.exists(file_path):
                        dest_path = os.path.join(backup_dir, file_path)
                        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                        if os.path.isdir(file_path):
                            shutil.copytree(file_path, dest_path, dirs_exist_ok=True)
                        else:
                            shutil.copy2(file_path, dest_path)

                Printer.warning(f"Local changes backed up to {backup_dir}/")

                # Reset to remote state
                reset_result = subprocess.run(['git', 'reset', '--hard', 'origin/main'],
                                            capture_output=True, text=True)
                if reset_result.returncode != 0:
                    raise Exception(reset_result.stderr)
            else:
                # Regular fast-forward merge
                pull_result = subprocess.run(['git', 'pull', '--ff-only', 'origin', 'main'],
                                           capture_output=True, text=True)
                if pull_result.returncode != 0:
                    raise Exception(pull_result.stderr)

            Printer.success("Update successful! Restart required")
            return True

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
            response = requests.get(url, timeout=30, stream=True)
            
            if filename == 'cve_db.json':
                # Handle CSV-to-JSON conversion with proper encoding
                cve_data = defaultdict(list)
                
                # Decode content using latin-1 to handle all byte values
                content = response.content.decode('latin-1')
                reader = csv.DictReader(io.StringIO(content), delimiter=',')

                for row in reader:
                    try:
                        if 'Name' in row and row['Name']:
                            parts = row['Name'].split('|')
                            if len(parts) > 1:
                                software = parts[1].lower().strip()
                                cve_entry = {
                                    'cve': parts[0].strip(),
                                    'severity': row.get('Phase', 'N/A').strip(),
                                    'description': row.get('Description', 'No description')
                                        .encode('latin-1').decode('utf-8', 'ignore').strip()
                                }
                                cve_data[software].append(cve_entry)
                    except UnicodeDecodeError as ude:
                        Printer.warning(f"Skipping row with invalid characters: {str(ude)}")
                        continue

                # Save with UTF-8 encoding and ensure_ascii=False
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(cve_data, f, indent=2, ensure_ascii=False)

            else:
                # Handle other files with UTF-8 encoding
                with open(filename, 'wb') as f:
                    f.write(response.content)

            Printer.success(f"Processed {filename}")

        except Exception as e:
            Printer.error(f"Failed to process {filename}: {str(e)}")
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
                    Printer.status(f"  {ip}")
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
        self.scan_active = False

        ThreatIntel.initialize_environment()
        self._load_databases()
        self._start_input_handler()

        if GitHubUpdater.check_update():
            sys.exit(0)

    def _start_input_handler(self):
        def input_listener():
            while True:
                input()
                if self.scan_active:
                    self._check_status(force=True)
        threading.Thread(target=input_listener, daemon=True).start()

    def _check_status(self, force=False):
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
        try:
            # Load JSON with mixed encoding support
            with open('cve_db.json', 'r', encoding='utf-8') as f:
                self.cve_db = json.load(f)
            
            # Load directories with UTF-8 and fallback to latin-1
            try:
                with open('directories.txt', 'r', encoding='utf-8') as f:
                    self.common_dirs = f.read().splitlines()
            except UnicodeDecodeError:
                with open('directories.txt', 'r', encoding='latin-1') as f:
                    self.common_dirs = f.read().splitlines()

        except Exception as e:
            Printer.error(f"Database load failed: {str(e)}")
            sys.exit(1)

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
        """Fixed port scan method with proper indentation"""
        try:
            self.scan_active = True
            Printer.status(f"Starting port scan on {ip} ({ports})")
            
            # Configure scan parameters
            scan_args = '-sS -sV -T4 --open --script vulners'
            self.nm.scan(ip, ports, arguments=scan_args)
            
            # Real-time progress tracking using XML output
            start_time = time.time()
            last_progress = 0
            
            while True:
                try:
                    # Get raw XML output
                    xml_output = self.nm.get_nmap_last_output()
                    if not xml_output:
                        break
                        
                    root = ET.fromstring(xml_output)
                    progress = root.find(".//taskprogress")
                    
                    if progress is not None:
                        current_progress = float(progress.get('percent', '0'))
                        elapsed = time.time() - start_time
                        
                        # Update progress if changed
                        if current_progress != last_progress:
                            self.progress.update_ports(current_progress, 100)
                            self._check_status()
                            last_progress = current_progress
                            
                        # Check completion
                        if current_progress >= 100.0:
                            break
                            
                    time.sleep(0.5)
                    
                except (ET.ParseError, AttributeError):
                    break
                except KeyboardInterrupt:
                    Printer.warning("Port scan interrupted by user")
                    return

            # Process results
            if ip not in self.nm.all_hosts():
                raise ValueError("Target not in scan results")

            host_data = self.nm[ip]
            open_ports = []
            
            for proto in host_data.all_protocols():
                ports = host_data[proto].keys()
                for port in ports:
                    service = host_data[proto][port]
                    open_ports.append({
                        'port': port,
                        'protocol': proto,
                        'service': f"{service['name']} {service.get('product', '')}",
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
        """Improved ExploitDB search using web scraping"""
        try:
            time.sleep(1)  # Respect rate limits
            headers = {
                'User-Agent': 'CyberGuardian/3.0 (+https://github.com/NikolisSecurity/CyberToolX)',
                'Accept-Language': 'en-US,en;q=0.5'
            }
            
            search_query = f"{service['service']} {service['version']}".strip()
            params = {'q': search_query}
            
            response = requests.get(
                'https://www.exploit-db.com/search',
                params=params,
                headers=headers,
                timeout=15
            )
            
            if response.status_code != 200:
                Printer.warning(f"Exploit DB search failed (HTTP {response.status_code})")
                return []

            soup = BeautifulSoup(response.text, 'html.parser')
            exploits = []
            
            for row in soup.select('table.table-exploits tr'):
                cols = row.select('td')
                if len(cols) >= 5:
                    try:
                        exploit_id = cols[1].text.strip()
                        description = cols[3].text.strip()
                        url = f"https://www.exploit-db.com{cols[1].find('a')['href']}"
                        exploits.append({
                            'id': exploit_id,
                            'description': description,
                            'url': url
                        })
                    except Exception as e:
                        Printer.warning(f"Skipping invalid exploit row: {str(e)}")
            
            return exploits[:3]  # Return top 3 results

        except Exception as e:
            Printer.warning(f"Exploit DB check failed: {str(e)}")
            return []
            
    def directory_enum(self, base_url):
        try:
            self.scan_active = True
            total_dirs = len(self.common_dirs)
            self.progress.update_dirs(0, total_dirs)
            completed = 0
            
            with ThreadPoolExecutor(max_workers=CONFIG['max_threads']) as executor:
                futures = {executor.submit(self._check_dir, base_url, dir): dir 
                          for dir in self.common_dirs}
                
                while completed < total_dirs:
                    done, _ = concurrent.futures.wait(
                        futures, 
                        timeout=1,
                        return_when=concurrent.futures.FIRST_COMPLETED
                    )
                    
                    for future in done:
                        try:
                            result = future.result()
                            if result:
                                self.findings['directories'].append(result)
                        except:
                            pass
                        completed += 1
                        self.progress.update_dirs(completed, total_dirs)
                        del futures[future]
                    
                    # Update status on each iteration
                    self._check_status()
            
            Printer.success(f"Found {len(self.findings['directories'])} valid directories")
        finally:
            self.scan_active = False

    def _check_dir(self, base_url, directory):
        try:
            url = f"{base_url.rstrip('/')}/{directory.lstrip('/')}"
            response = requests.get(url, timeout=3, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                return {'url': url, 'status': response.status_code}
        except:
            return None

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
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"""
            <html>
                <head>
                    <title>CyberGuardian Report - {self.findings['target']}</title>
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
                    <h1>Security Report for {self.findings['target']}</h1>
                    <h3>Scan ID: {self.session_id}</h3>

                    <h2>Network Discovery</h2>
                    <h3>Resolved IP Addresses</h3>
                    <ul>
                        {"".join(f"<li class='ip'>{ip}</li>" for ip in self.findings['ips'])}
                    </ul>

                    <h3>Open Ports & Services</h3>
                    <ul>
                        {"".join(
                            f"<li><b>{service['ip']}:{service['port']}</b> - {service['service']} "
                            f"(v{service['version']})</li>"
                            for service in self.findings['ports']
                        )}
                    </ul>

                    <h2>Security Findings</h2>
                    <h3>Vulnerabilities ({len(self.findings['vulnerabilities'])})</h3>
                    <ul>
                        {"".join(
                            f"<li class='vulnerability'>{vuln['cve']} ({vuln['severity']})<br>"
                            f"<small>{vuln['description']}</small><br>"
                            f"<i>Affected service: {vuln['service']} on {vuln['ip']}:{vuln['port']}</i></li>"
                            for vuln in self.findings['vulnerabilities']
                        )}
                    </ul>

                    <h3>Potential Exploits ({len(self.findings['exploits'])})</h3>
                    <ul>
                        {"".join(
                            f"<li class='exploit'><a href='{exploit['url']}' target='_blank'>"
                            f"Exploit {exploit['exploit_id']}</a>: {exploit['description']}<br>"
                            f"<i>Target service: {exploit['service']}</i></li>"
                            for exploit in self.findings['exploits']
                        )}
                    </ul>

                    <h2>Web Directory Discovery ({len(self.findings['directories'])})</h2>
                    <ul>
                        {"".join(
                            f"<li><a href='{dir['url']}' target='_blank'>{dir['url']}</a> "
                            f"(HTTP {dir['status']})</li>"
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
