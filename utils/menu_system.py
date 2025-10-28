"""Interactive menu system for NPS Tool"""

import os
import sys
import json
import time
import getpass
from datetime import datetime
from pathlib import Path
from .color_compat import colored
from .ascii_art import AsciiArt
from .command_parser import CommandParser

# Import configuration
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CONFIG, DEFAULTS


class MenuSystem:
    """Interactive menu-driven interface"""

    def __init__(self):
        self.running = True
        self.current_target = None
        self.scan_results = {}

        # Configuration settings
        self.config = {
            'proxy': None,
            'threads': CONFIG.get('max_threads', 50),
            'timeout': CONFIG.get('timeout', 5),
            'verbose': DEFAULTS.get('verbose', False),
            'user_agent': CONFIG.get('user_agent', 'CyberGuardian/2.0'),
            'verify_ssl': DEFAULTS.get('verify_ssl', False),
        }

        # Scan history tracking
        self.scan_history = []

        # Metrics tracking
        self.metrics_file = Path(__file__).parent.parent / 'data' / 'command_metrics.json'
        self._ensure_metrics_file()

        # Define all available commands
        self.commands = {
            # Main Menu
            'help': 'Display available commands and usage',
            'clear': 'Clear the screen',
            'exit': 'Exit NPS Tool',
            'quit': 'Exit NPS Tool',
            'banner': 'Display the main banner',
            'about': 'About NPS Tool',

            # Target Management
            'target': 'Set target for scanning (usage: target <ip/domain>)',
            'showtarget': 'Display current target',
            'cleartarget': 'Clear current target',

            # Web Application Testing
            'webscan': 'Complete web application scan',
            'dirscan': 'Directory and file enumeration',
            'sqlmap': 'SQL injection testing',
            'xsstest': 'XSS vulnerability testing',
            'csrftest': 'CSRF vulnerability testing',
            'headerscan': 'Security headers analysis',
            'sslscan': 'SSL/TLS configuration scan',
            'wafscan': 'WAF detection and fingerprinting',
            'cmsscan': 'CMS detection and version check',
            'apiscan': 'API endpoint discovery',
            'graphql': 'GraphQL introspection',
            'jwtscan': 'JWT token analysis',
            'robots': 'Check robots.txt and sitemap.xml',

            # DNS/Subdomain
            'dnsenum': 'DNS enumeration',
            'subdomain': 'Subdomain enumeration',

            # Web OSINT
            'emailharvest': 'Email address harvesting',
            'metadata': 'Extract file metadata',
            'techstack': 'Detect web technology stack',

            # Reporting & Results
            'results': 'Show scan results',
            'report': 'Generate comprehensive report',
            'export': 'Export results to file',
            'history': 'View scan history',
            'compare': 'Compare multiple scan results',

            # Configuration
            'settings': 'View/modify settings',
            'proxy': 'Configure proxy settings',
            'threads': 'Set thread count',
            'timeout': 'Set connection timeout',
            'verbose': 'Toggle verbose output',
            'update': 'Update tool databases',

            # Advanced
            'script': 'Run automation script',
            'schedule': 'Schedule recurring scans',
            'monitor': 'Continuous monitoring mode',
            'honeypot': 'Deploy honeypot',
            'custom': 'Execute custom command',

            # Analytics & Metrics
            'stats': 'Display command usage statistics',
            'timeline': 'Show command usage timeline',
            'performance': 'Show command performance metrics',
            'exportstats': 'Export analytics to report file'
        }

        self.parser = CommandParser(self.commands)

    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name != 'nt' else 'cls')

    def _ensure_metrics_file(self):
        """Initialize metrics file if it doesn't exist"""
        try:
            if not self.metrics_file.exists():
                # Create parent directory if needed
                self.metrics_file.parent.mkdir(parents=True, exist_ok=True)
                # Create initial empty structure
                initial_data = {
                    "metrics": [],
                    "summary": {
                        "total_commands": 0,
                        "last_updated": None
                    }
                }
                self.metrics_file.write_text(json.dumps(initial_data, indent=2))
            else:
                # Verify file is valid JSON, reset if corrupted
                try:
                    json.loads(self.metrics_file.read_text())
                except json.JSONDecodeError:
                    initial_data = {
                        "metrics": [],
                        "summary": {
                            "total_commands": 0,
                            "last_updated": None
                        }
                    }
                    self.metrics_file.write_text(json.dumps(initial_data, indent=2))
        except (OSError, PermissionError):
            # Silently fail - don't crash program if metrics can't be initialized
            pass

    def _load_metrics(self):
        """Load metrics from JSON file"""
        try:
            if self.metrics_file.exists():
                data = json.loads(self.metrics_file.read_text())
                return data
            else:
                return {
                    "metrics": [],
                    "summary": {
                        "total_commands": 0,
                        "last_updated": None
                    }
                }
        except (OSError, json.JSONDecodeError, PermissionError):
            # Return empty structure on any error
            return {
                "metrics": [],
                "summary": {
                    "total_commands": 0,
                    "last_updated": None
                }
            }

    def _save_metric(self, command, duration, status, error=None):
        """Append a single metric entry"""
        try:
            # Load current metrics
            data = self._load_metrics()

            # Create new metric entry
            metric_entry = {
                "command": command,
                "timestamp": datetime.now().isoformat(),
                "duration": round(duration, 3),
                "status": status,
                "target": self.current_target,
                "error": error
            }

            # Append to metrics list
            data["metrics"].append(metric_entry)

            # Update summary
            data["summary"]["total_commands"] = len(data["metrics"])
            data["summary"]["last_updated"] = metric_entry["timestamp"]

            # Save back to file
            self.metrics_file.write_text(json.dumps(data, indent=2))
        except (OSError, PermissionError):
            # Silently fail - don't crash program if metrics can't be saved
            pass

    def display_prompt(self):
        """Display command prompt"""
        return colored('[>] ', 'green')

    def display_help(self, category=None):
        """Display help information"""
        self.clear_screen()
        print(colored("\n╔═══════════════════════ COMMAND REFERENCE ═══════════════════════╗\n", 'cyan', attrs=['bold']))

        categories = {
            'Main': ['help', 'clear', 'exit', 'quit', 'banner', 'about'],
            'Target Management': ['target', 'showtarget', 'cleartarget'],
            'Web Testing': ['webscan', 'dirscan', 'sqlmap', 'xsstest', 'csrftest', 'headerscan', 'sslscan', 'wafscan', 'cmsscan', 'apiscan', 'graphql', 'jwtscan', 'robots'],
            'DNS & Subdomain': ['dnsenum', 'subdomain'],
            'Web OSINT': ['emailharvest', 'metadata', 'techstack'],
            'Reporting': ['results', 'report', 'export', 'history', 'compare'],
            'Configuration': ['settings', 'proxy', 'threads', 'timeout', 'verbose', 'update'],
            'Analytics': ['stats', 'timeline', 'performance', 'exportstats'],
            'Advanced': ['script', 'schedule', 'monitor', 'honeypot', 'custom']
        }

        for cat_name, cmd_list in categories.items():
            print(colored(f"  {cat_name}:", 'yellow', attrs=['bold']))
            for cmd in cmd_list:
                desc = self.commands.get(cmd, 'No description')
                print(f"    {colored(cmd, 'green'):<20} - {colored(desc, 'white')}")
            print()

        print(colored("╚════════════════════════════════════════════════════════════════╝\n", 'cyan', attrs=['bold']))

    def display_about(self):
        """Display about information"""
        self.clear_screen()
        about_text = f"""
{colored('╔════════════════════════════════════════════════════════════════╗', 'cyan')}
{colored('║', 'cyan')}                         ABOUT NPS TOOL                         {colored('║', 'cyan')}
{colored('╚════════════════════════════════════════════════════════════════╝', 'cyan')}

{colored('Version:', 'yellow')} 1.0 Web Security Edition

{colored('Description:', 'yellow')}
  NPS Tool (Network Pentesting Suite) is a specialized web application
  security testing platform designed for penetration testers and security
  researchers. Focused exclusively on web vulnerabilities, subdomain
  enumeration, and web-based reconnaissance.

{colored('Features:', 'yellow')}
  • 20+ Web Security Testing Tools
  • Interactive Command Interface
  • Target Management System
  • SQL Injection Testing
  • XSS & CSRF Detection
  • SSL/TLS Security Analysis
  • WAF Detection & Fingerprinting
  • CMS & Technology Stack Detection
  • API & GraphQL Testing
  • Subdomain Enumeration
  • Web-focused OSINT Tools
  • Comprehensive Reporting
  • Analytics & Performance Tracking

{colored('Legal Notice:', 'red', attrs=['bold'])}
  This tool is for AUTHORIZED TESTING ONLY. Unauthorized access to
  computer systems is illegal. Always obtain written permission before
  testing any systems you do not own.

{colored('Author:', 'yellow')} NPS Development Team
{colored('License:', 'yellow')} For authorized security professionals only
{colored('Website:', 'yellow')} https://github.com/NikolisSecurity/CyberToolX

{colored('Press Enter to continue...', 'cyan')}
        """
        print(about_text)
        input()

    def run(self):
        """Main menu loop"""
        # Show loading screen
        self.clear_screen()
        AsciiArt.loading_screen()
        self.clear_screen()

        # Show main banner
        print(AsciiArt.main_banner(self.current_target))

        # Welcome message with username
        try:
            username = getpass.getuser()
        except Exception:
            username = "User"

        print(colored(f"Hello @{username}. Welcome to NPS Tool", 'cyan'))
        print(colored("To view the list of commands, type help", 'cyan'))
        print()

        while self.running:
            try:
                user_input = input(self.display_prompt())

                if not user_input.strip():
                    continue

                command, args = self.parser.parse(user_input)

                if command is None:
                    continue

                # Execute command
                self.execute_command(command, args)

            except KeyboardInterrupt:
                print(f"\n\n{colored('Use', 'yellow')} {colored('exit', 'green', attrs=['bold'])} {colored('to quit', 'yellow')}\n")
                continue
            except EOFError:
                break
            except Exception as e:
                print(f"\n{colored('✗ Error:', 'red', attrs=['bold'])} {str(e)}\n")

    def execute_command(self, command, args):
        """Execute a parsed command"""
        # START METRICS TRACKING
        start_time = time.time()
        status = "success"
        error_msg = None

        try:
            # Main commands
            if command == 'help':
                self.display_help()
            elif command == 'clear':
                self.clear_screen()
                print(AsciiArt.main_banner(self.current_target))
            elif command in ['exit', 'quit']:
                self.running = False
                print(f"\n{colored('Shutting down NPS Tool...', 'cyan')}")
                print(colored('Stay safe. Stay ethical. 👾\n', 'green'))
            elif command == 'banner':
                self.clear_screen()
                print(AsciiArt.main_banner(self.current_target))
            elif command == 'about':
                self.display_about()

            # Target management
            elif command == 'target':
                if args:
                    self.current_target = args[0]
                    AsciiArt.success_message(f"Target set to: {self.current_target}")
                else:
                    AsciiArt.error_message("Usage: target <ip/domain>")
            elif command == 'showtarget':
                if self.current_target:
                    print(f"\n{colored('Current target:', 'cyan')} {colored(self.current_target, 'green', attrs=['bold'])}\n")
                else:
                    AsciiArt.warning_message("No target set. Use 'target <ip/domain>' to set one.")
            elif command == 'cleartarget':
                self.current_target = None
                AsciiArt.success_message("Target cleared")

            # Analytics commands
            elif command == 'stats':
                self.display_stats()
            elif command == 'timeline':
                self.display_timeline()
            elif command == 'performance':
                self.display_performance()
            elif command == 'exportstats':
                self.export_stats()

            # Tool execution - placeholder for now
            else:
                self.execute_tool(command, args)

        except Exception as e:
            status = "error"
            error_msg = str(e)
            # Re-raise the exception so normal error handling still works
            raise

        finally:
            # ALWAYS log metrics, even if command failed
            duration = time.time() - start_time
            self._save_metric(command, duration, status, error_msg)

    def execute_tool(self, tool, args):
        """Execute a security tool"""
        if not self.current_target and tool not in ['settings', 'update']:
            AsciiArt.error_message("No target set. Use 'target <ip/domain>' first.")
            return

        try:
            # Import tools
            from tools.web_tools import WebTools
            from tools.network_tools import NetworkTools
            from tools.osint_tools import OSINTTools

            # Web application tools
            if tool == 'headerscan':
                web = WebTools(self.current_target)
                results = web.headers_scan()
                self.scan_results['headerscan'] = results

            elif tool == 'sslscan':
                web = WebTools(self.current_target)
                results = web.ssl_scan()
                self.scan_results['sslscan'] = results

            elif tool == 'robots':
                web = WebTools(self.current_target)
                web.robots_check()

            elif tool == 'wafscan':
                web = WebTools(self.current_target)
                results = web.waf_detect()
                self.scan_results['wafscan'] = results

            elif tool == 'cmsscan':
                web = WebTools(self.current_target)
                results = web.cms_detect()
                self.scan_results['cmsscan'] = results

            # Network tools (DNS/subdomain only)
            elif tool == 'dnsenum':
                net = NetworkTools(self.current_target)
                net.dns_enum()

            elif tool == 'subdomain':
                net = NetworkTools(self.current_target)
                results = net.subdomain_enum()
                self.scan_results['subdomain'] = results

            # OSINT tools (web-focused only)
            elif tool == 'emailharvest':
                osint = OSINTTools(self.current_target)
                results = osint.email_harvest()
                self.scan_results['emailharvest'] = results

            elif tool == 'metadata':
                target_url = args[0] if args else self.current_target
                osint = OSINTTools(target_url)
                results = osint.metadata_extract(target_url)
                self.scan_results['metadata'] = results

            elif tool == 'techstack':
                osint = OSINTTools(self.current_target)
                results = osint.tech_stack_detect()
                self.scan_results['techstack'] = results

            # Results and reporting
            elif tool == 'results':
                self.show_results()

            # Tools not yet implemented
            else:
                print(f"\n{colored('⚡', 'yellow')} Tool: {colored(tool, 'green', attrs=['bold'])}")
                AsciiArt.info_message(f"Tool '{tool}' integration coming soon!")

        except ImportError as e:
            AsciiArt.error_message(f"Failed to load tool: {str(e)}")
        except Exception as e:
            AsciiArt.error_message(f"Tool execution failed: {str(e)}")

    def show_results(self):
        """Display collected scan results"""
        if not self.scan_results:
            AsciiArt.info_message("No scan results yet. Run some scans first!")
            return

        self.clear_screen()
        print(colored("\n╔═══════════════════════ SCAN RESULTS ═══════════════════════╗\n", 'green', attrs=['bold']))

        for scan_type, results in self.scan_results.items():
            print(f"{colored(scan_type.upper(), 'cyan', attrs=['bold'])}:")
            if isinstance(results, list):
                print(f"  Found {len(results)} items")
            elif isinstance(results, dict):
                print(f"  {len(results)} entries")
            else:
                print(f"  {results}")
            print()

        print(colored("╚════════════════════════════════════════════════════════════╝\n", 'green', attrs=['bold']))
        print(f"{colored('💾 Tip:', 'cyan')} Use {colored('report', 'green', attrs=['bold'])} to generate a full report\n")

    def display_stats(self):
        """Show usage statistics"""
        self.clear_screen()
        data = self._load_metrics()
        metrics = data.get("metrics", [])

        if not metrics:
            print(colored("\n╔═══════════════════ COMMAND USAGE STATISTICS ════════════════════╗\n", 'cyan', attrs=['bold']))
            print(f"  {colored('No command history yet. Start using commands to see statistics!', 'yellow')}\n")
            print(colored("╚══════════════════════════════════════════════════════════════════╝\n", 'cyan', attrs=['bold']))
            return

        # Calculate statistics
        total_commands = len(metrics)
        success_count = sum(1 for m in metrics if m.get("status") == "success")
        failed_count = total_commands - success_count
        success_rate = (success_count / total_commands * 100) if total_commands > 0 else 0

        # Most used commands
        command_counts = {}
        for m in metrics:
            cmd = m.get("command", "unknown")
            command_counts[cmd] = command_counts.get(cmd, 0) + 1
        most_used = sorted(command_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # Recent activity (last 24 hours)
        from datetime import timedelta
        now = datetime.now()
        recent_count = 0
        for m in metrics:
            try:
                timestamp = datetime.fromisoformat(m.get("timestamp", ""))
                if now - timestamp < timedelta(hours=24):
                    recent_count += 1
            except:
                pass

        # Active targets
        target_counts = {}
        for m in metrics:
            target = m.get("target")
            if target:
                target_counts[target] = target_counts.get(target, 0) + 1
        active_targets = sorted(target_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        # Display
        print(colored("\n╔═══════════════════ COMMAND USAGE STATISTICS ════════════════════╗\n", 'cyan', attrs=['bold']))

        print(f"  {colored('Total Commands Executed:', 'yellow')} {colored(str(total_commands), 'green')}")

        # Success rate color coding
        if success_rate > 80:
            rate_color = 'green'
        elif success_rate >= 50:
            rate_color = 'yellow'
        else:
            rate_color = 'red'
        print(f"  {colored('Success Rate:', 'yellow')} {colored(f'{success_rate:.1f}%', rate_color)}")

        print(f"  {colored('Failed Commands:', 'yellow')} {colored(str(failed_count), 'red')}")
        print(f"  {colored('Commands in Last 24h:', 'yellow')} {colored(str(recent_count), 'green')}")

        print(f"\n  {colored('Most Used Commands:', 'yellow')}")
        for i, (cmd, count) in enumerate(most_used, 1):
            print(f"    {colored(f'{i}.', 'cyan')} {colored(cmd, 'green')} ({count} times)")

        if active_targets:
            print(f"\n  {colored('Active Targets:', 'yellow')}")
            for target, count in active_targets:
                print(f"    {colored(target, 'cyan')} ({count} commands)")

        print(colored("\n╚══════════════════════════════════════════════════════════════════╝", 'cyan', attrs=['bold']))
        print(f"{colored('💡 Tip:', 'cyan')} Use {colored('timeline', 'green', attrs=['bold'])} and {colored('performance', 'green', attrs=['bold'])} for more details\n")

    def display_timeline(self):
        """Show command usage over time"""
        self.clear_screen()
        data = self._load_metrics()
        metrics = data.get("metrics", [])

        if not metrics:
            print(colored("\n╔═══════════════════ COMMAND USAGE TIMELINE ══════════════════════╗\n", 'cyan', attrs=['bold']))
            print(f"  {colored('No command history available', 'yellow')}\n")
            print(colored("╚══════════════════════════════════════════════════════════════════╝\n", 'cyan', attrs=['bold']))
            return

        # Group by date
        from datetime import timedelta
        date_counts = {}
        today_hourly = {}
        now = datetime.now()
        today_date = now.date()

        for m in metrics:
            try:
                timestamp_str = m.get("timestamp", "")
                timestamp = datetime.fromisoformat(timestamp_str)
                date = timestamp.date()
                date_counts[date] = date_counts.get(date, 0) + 1

                # Today's hourly breakdown
                if date == today_date:
                    hour = timestamp.hour
                    today_hourly[hour] = today_hourly.get(hour, 0) + 1
            except:
                pass

        # Get last 7 days
        last_7_days = [(now - timedelta(days=i)).date() for i in range(6, -1, -1)]

        print(colored("\n╔═══════════════════ COMMAND USAGE TIMELINE ══════════════════════╗\n", 'cyan', attrs=['bold']))

        print(f"  {colored('Last 7 Days:', 'yellow', attrs=['bold'])}")
        for date in last_7_days:
            count = date_counts.get(date, 0)
            date_str = date.strftime('%Y-%m-%d')
            if count > 0:
                print(f"    {colored(date_str, 'cyan')}: {colored(f'{count} commands', 'green')}")
            else:
                print(f"    {colored(date_str, 'cyan')}: {colored(f'{count} commands', 'white', attrs=['dark'])}")

        if today_hourly:
            hourly_title = "Today's Hourly Breakdown:"
            print(f"\n  {colored(hourly_title, 'yellow', attrs=['bold'])}")
            for hour in sorted(today_hourly.keys()):
                count = today_hourly[hour]
                hour_range = f"{hour:02d}:00-{hour:02d}:59"
                print(f"    {colored(hour_range, 'yellow')}: {colored(f'{count} commands', 'green')}")

        print(colored("\n╚══════════════════════════════════════════════════════════════════╝\n", 'cyan', attrs=['bold']))

    def display_performance(self):
        """Show command performance metrics"""
        self.clear_screen()
        data = self._load_metrics()
        metrics = data.get("metrics", [])

        if not metrics:
            print(colored("\n╔═══════════════════ COMMAND PERFORMANCE METRICS ═════════════════╗\n", 'cyan', attrs=['bold']))
            print(f"  {colored('No performance data available', 'yellow')}\n")
            print(colored("╚══════════════════════════════════════════════════════════════════╝\n", 'cyan', attrs=['bold']))
            return

        # Calculate performance stats per command
        command_stats = {}
        for m in metrics:
            cmd = m.get("command", "unknown")
            duration = m.get("duration", 0)
            status = m.get("status", "unknown")

            if cmd not in command_stats:
                command_stats[cmd] = {
                    "durations": [],
                    "errors": 0,
                    "total": 0
                }

            command_stats[cmd]["durations"].append(duration)
            command_stats[cmd]["total"] += 1
            if status == "error":
                command_stats[cmd]["errors"] += 1

        # Calculate averages and max
        for cmd, stats in command_stats.items():
            stats["max"] = max(stats["durations"])
            stats["avg"] = sum(stats["durations"]) / len(stats["durations"])
            stats["error_rate"] = (stats["errors"] / stats["total"] * 100) if stats["total"] > 0 else 0

        # Slowest commands (by max duration)
        slowest = sorted(command_stats.items(), key=lambda x: x[1]["max"], reverse=True)[:10]

        # Average durations (only commands with avg > 1 second)
        avg_slow = [(cmd, stats) for cmd, stats in command_stats.items() if stats["avg"] > 1.0]
        avg_slow.sort(key=lambda x: x[1]["avg"], reverse=True)

        # Fastest commands (avg < 0.1 seconds)
        fastest = [(cmd, stats) for cmd, stats in command_stats.items() if stats["avg"] < 0.1]
        fastest.sort(key=lambda x: x[1]["avg"])[:10]

        # Error-prone commands
        error_prone = [(cmd, stats) for cmd, stats in command_stats.items() if stats["error_rate"] > 0]
        error_prone.sort(key=lambda x: x[1]["error_rate"], reverse=True)[:10]

        print(colored("\n╔═══════════════════ COMMAND PERFORMANCE METRICS ═════════════════╗\n", 'cyan', attrs=['bold']))

        # Slowest commands
        if slowest:
            print(f"  {colored('Slowest Commands (Maximum Duration):', 'yellow', attrs=['bold'])}")
            for cmd, stats in slowest:
                duration = stats["max"]
                if duration > 10:
                    color = 'red'
                elif duration >= 1:
                    color = 'yellow'
                else:
                    color = 'white'
                print(f"    {colored(cmd, color)}: {colored(f'{duration:.3f}s', color)}")

        # Average execution times
        if avg_slow:
            print(f"\n  {colored('Average Execution Times (>1s):', 'yellow', attrs=['bold'])}")
            for cmd, stats in avg_slow:
                avg_duration = stats["avg"]
                run_count = stats["total"]
                print(f"    {colored(cmd, 'yellow')}: {colored(f'{avg_duration:.3f}s avg', 'white')} ({run_count} runs)")

        # Fastest commands
        if fastest:
            print(f"\n  {colored('Fastest Commands:', 'yellow', attrs=['bold'])}")
            for cmd, stats in fastest[:10]:
                duration = stats["avg"]
                print(f"    {colored(cmd, 'green')}: {colored(f'{duration:.3f}s', 'green')}")

        # Error-prone commands
        if error_prone:
            print(f"\n  {colored('Error-Prone Commands:', 'yellow', attrs=['bold'])}")
            for cmd, stats in error_prone:
                error_rate = stats["error_rate"]
                error_count = stats["errors"]
                total_count = stats["total"]
                if error_rate > 20:
                    color = 'red'
                elif error_rate > 10:
                    color = 'yellow'
                else:
                    color = 'white'
                print(f"    {colored(cmd, color)}: {colored(f'{error_rate:.1f}% failures', color)} ({error_count}/{total_count})")
        else:
            print(f"\n  {colored('Error-Prone Commands:', 'yellow', attrs=['bold'])}")
            print(f"    {colored('No failed commands - perfect record!', 'green')}")

        print(colored("\n╚══════════════════════════════════════════════════════════════════╝\n", 'cyan', attrs=['bold']))

    def export_stats(self):
        """Export analytics to a report file"""
        data = self._load_metrics()
        metrics = data.get("metrics", [])

        # Generate timestamp for filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = self.metrics_file.parent / f'analytics_report_{timestamp}.txt'

        # Build report
        report_lines = []
        report_lines.append("╔══════════════════════════════════════════════════════════════════╗")
        report_lines.append("║                 NPS TOOL ANALYTICS REPORT                        ║")
        report_lines.append("╚══════════════════════════════════════════════════════════════════╝")
        report_lines.append("")
        report_lines.append(f"Generated: {datetime.now().isoformat()}")
        report_lines.append("")

        if not metrics:
            report_lines.append("=== NO DATA AVAILABLE ===")
            report_lines.append("No command history found. Start using commands to generate analytics.")
        else:
            # Usage Statistics
            total_commands = len(metrics)
            success_count = sum(1 for m in metrics if m.get("status") == "success")
            success_rate = (success_count / total_commands * 100) if total_commands > 0 else 0

            report_lines.append("=== USAGE STATISTICS ===")
            report_lines.append(f"Total Commands Executed: {total_commands}")
            report_lines.append(f"Success Rate: {success_rate:.1f}%")
            report_lines.append(f"Failed Commands: {total_commands - success_count}")
            report_lines.append("")

            # Top Commands
            command_counts = {}
            for m in metrics:
                cmd = m.get("command", "unknown")
                command_counts[cmd] = command_counts.get(cmd, 0) + 1
            most_used = sorted(command_counts.items(), key=lambda x: x[1], reverse=True)[:20]

            report_lines.append("=== TOP COMMANDS ===")
            for i, (cmd, count) in enumerate(most_used, 1):
                report_lines.append(f"{i}. {cmd}: {count} times")
            report_lines.append("")

            # Performance Metrics
            command_stats = {}
            for m in metrics:
                cmd = m.get("command", "unknown")
                duration = m.get("duration", 0)
                if cmd not in command_stats:
                    command_stats[cmd] = []
                command_stats[cmd].append(duration)

            report_lines.append("=== PERFORMANCE METRICS ===")
            for cmd in sorted(command_stats.keys()):
                durations = command_stats[cmd]
                avg_dur = sum(durations) / len(durations)
                max_dur = max(durations)
                report_lines.append(f"{cmd}: avg={avg_dur:.3f}s, max={max_dur:.3f}s, runs={len(durations)}")
            report_lines.append("")

            # Timeline (last 30 days)
            from datetime import timedelta
            date_counts = {}
            now = datetime.now()
            for m in metrics:
                try:
                    timestamp = datetime.fromisoformat(m.get("timestamp", ""))
                    date = timestamp.date()
                    date_counts[date] = date_counts.get(date, 0) + 1
                except:
                    pass

            last_30_days = [(now - timedelta(days=i)).date() for i in range(29, -1, -1)]
            report_lines.append("=== TIMELINE (Last 30 Days) ===")
            for date in last_30_days:
                count = date_counts.get(date, 0)
                if count > 0:
                    report_lines.append(f"{date.strftime('%Y-%m-%d')}: {count} commands")
            report_lines.append("")

            # Full Metrics Log
            report_lines.append("=== FULL METRICS LOG ===")
            for m in metrics:
                timestamp = m.get("timestamp", "unknown")
                command = m.get("command", "unknown")
                duration = m.get("duration", 0)
                status = m.get("status", "unknown")
                target = m.get("target", "none")
                error = m.get("error")
                error_str = f", error={error}" if error else ""
                report_lines.append(f"[{timestamp}] {command}: duration={duration:.3f}s, status={status}, target={target}{error_str}")

        # Write report to file
        try:
            report_content = "\n".join(report_lines)
            output_file.write_text(report_content)
            AsciiArt.success_message(f"Analytics report exported to: {output_file}")
            return str(output_file)
        except (OSError, PermissionError) as e:
            AsciiArt.error_message(f"Failed to export report: {str(e)}")
            return None

    # CONFIGURATION COMMANDS
    def show_settings(self):
        """Display current configuration settings"""
        print(colored("\n╔═══════════════════════ CURRENT SETTINGS ═══════════════════════╗\n", 'red', attrs=['bold']))

        print(f"  {colored('NETWORK CONFIGURATION:', 'yellow', attrs=['bold'])}")
        proxy_status = self.config['proxy'] if self.config['proxy'] else colored('None (direct connection)', 'white')
        print(f"    Proxy:           {proxy_status}")
        print(f"    Timeout:         {colored(f"{self.config['timeout']} seconds", 'white')}")
        ssl_verify = colored('Disabled', 'red') if not self.config['verify_ssl'] else colored('Enabled', 'green')
        print(f"    SSL Verify:      {ssl_verify}")
        print(f"    User Agent:      {colored(self.config['user_agent'], 'white')}")

        print(f"\n  {colored('SCAN CONFIGURATION:', 'yellow', attrs=['bold'])}")
        print(f"    Threads:         {colored(f"{self.config['threads']} (max concurrent)", 'white')}")
        verbose_status = colored('Enabled', 'green') if self.config['verbose'] else colored('Disabled', 'white')
        print(f"    Verbose Mode:    {verbose_status}")

        print(colored("\n╚════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))
        print(f"{colored('💡 Tip:', 'blue')} Use individual commands to modify settings:")
        print(f"  • proxy <url>")
        print(f"  • threads <count>")
        print(f"  • timeout <seconds>")
        print(f"  • verbose\n")

    def set_proxy(self, args):
        """Configure proxy settings"""
        import re

        if not args or not args[0]:
            # Clear proxy
            self.config['proxy'] = None
            AsciiArt.success_message("Proxy cleared - using direct connection")
            return

        proxy_url = args[0]

        # Validate proxy format
        proxy_pattern = r'^(http|https|socks5)://[a-zA-Z0-9\-\.]+:\d+$'
        if not re.match(proxy_pattern, proxy_url):
            AsciiArt.error_message("Invalid proxy format. Use: http://host:port or https://host:port or socks5://host:port")
            return

        # Test proxy connection
        try:
            import requests
            print(f"\n{colored('Testing proxy connection...', 'yellow')}")
            proxies = {'http': proxy_url, 'https': proxy_url}
            response = requests.get('https://httpbin.org/ip', proxies=proxies, timeout=10)

            if response.status_code == 200:
                ip_info = response.json()
                self.config['proxy'] = proxy_url
                AsciiArt.success_message(f"Proxy configured: {proxy_url}")
                print(f"{colored('✓', 'green')} Connection test successful")
                print(f"  Your IP (via proxy): {colored(ip_info.get('origin', 'Unknown'), 'green')}\n")
                print(f"{colored('💡 Tip:', 'blue')} All requests will now use this proxy")
                print(f"{colored('⚠', 'yellow')} Warning: Some targets may block proxy connections\n")
            else:
                AsciiArt.error_message("Proxy connection test failed")
        except Exception as e:
            AsciiArt.error_message(f"Proxy test failed: {str(e)}")

    def set_threads(self, args):
        """Set thread count for concurrent operations"""
        if not args or not args[0]:
            AsciiArt.error_message("Usage: threads <count>")
            return

        try:
            thread_count = int(args[0])
            if thread_count < 1 or thread_count > 100:
                AsciiArt.error_message("Thread count must be between 1 and 100")
                return

            self.config['threads'] = thread_count
            CONFIG['max_threads'] = thread_count  # Update global config
            AsciiArt.success_message(f"Thread count set to: {thread_count}")

            print(f"\n{colored('RECOMMENDATIONS:', 'yellow', attrs=['bold'])}")
            print(f"  1-10 threads:    Slow/rate-limited targets")
            print(f"  10-30 threads:   Normal web applications")
            print(f"  30-50 threads:   Fast servers, good connection")
            print(f"  50-100 threads:  Very fast servers, testing only\n")
            print(f"{colored('⚠', 'yellow')} Warning: High thread counts may trigger WAF/IDS\n")
        except ValueError:
            AsciiArt.error_message("Thread count must be a valid number")

    def set_timeout(self, args):
        """Set connection timeout"""
        if not args or not args[0]:
            AsciiArt.error_message("Usage: timeout <seconds>")
            return

        try:
            timeout = float(args[0])
            if timeout < 1 or timeout > 60:
                AsciiArt.error_message("Timeout must be between 1 and 60 seconds")
                return

            self.config['timeout'] = timeout
            CONFIG['timeout'] = timeout  # Update global config
            AsciiArt.success_message(f"Connection timeout set to: {timeout} seconds")

            print(f"\n{colored('💡 Tip:', 'blue')} Lower timeout = faster scans but may miss slow servers")
            print(f"{colored('💡 Tip:', 'blue')} Higher timeout = more reliable but slower scans\n")
        except ValueError:
            AsciiArt.error_message("Timeout must be a valid number")

    def toggle_verbose(self):
        """Toggle verbose output mode"""
        self.config['verbose'] = not self.config['verbose']
        DEFAULTS['verbose'] = self.config['verbose']  # Update global default

        if self.config['verbose']:
            AsciiArt.success_message("Verbose mode ENABLED")
            print(f"\n{colored('You will now see:', 'yellow')}")
            print(f"  • Detailed HTTP request/response information")
            print(f"  • Full error stack traces")
            print(f"  • Debug logging")
            print(f"  • Timing information for each operation\n")
            print(f"{colored('💡 Tip:', 'blue')} Use 'verbose' again to disable\n")
        else:
            AsciiArt.success_message("Verbose mode DISABLED")
            print(f"\n{colored('Output will be concise and focused on results.', 'white')}\n")
            print(f"{colored('💡 Tip:', 'blue')} Use 'verbose' again to enable detailed output\n")

    def update_databases(self):
        """Update tool databases (wordlists, CVE data)"""
        import requests
        from pathlib import Path

        print(colored("\n╔═══════════════════════ UPDATING DATABASES ═══════════════════════╗\n", 'red', attrs=['bold']))
        print(f"{colored('Downloading wordlists and databases...', 'yellow')}\n")

        data_dir = Path(__file__).parent.parent / 'data'
        data_dir.mkdir(exist_ok=True)

        downloads = [
            {
                'name': 'Directory wordlist (common.txt)',
                'url': CONFIG.get('dir_list_url'),
                'file': data_dir / 'directories.txt',
                'source': 'SecLists/Discovery/Web-Content'
            },
            {
                'name': 'Subdomain wordlist (subdomains-top1million-5000.txt)',
                'url': CONFIG.get('subdomain_list_url'),
                'file': data_dir / 'subdomains.txt',
                'source': 'SecLists/Discovery/DNS'
            }
        ]

        success_count = 0
        for item in downloads:
            try:
                print(f"{colored('Downloading', 'yellow')} {item['name']}...")
                response = requests.get(item['url'], timeout=30)
                response.raise_for_status()

                item['file'].write_text(response.text)
                lines = len(response.text.splitlines())

                print(f"{colored('✓', 'green')} {item['name']}")
                print(f"  Source: {colored(item['source'], 'white')}")
                print(f"  Size: {colored(f'{lines:,} entries', 'green')}\n")
                success_count += 1
            except Exception as e:
                print(f"{colored('✗', 'red')} Failed to download {item['name']}")
                print(f"  Error: {colored(str(e), 'red')}\n")

        if success_count == len(downloads):
            print(colored("UPDATE COMPLETE", 'green', attrs=['bold']))
            print(f"{colored('All databases are up to date.', 'white')}\n")
        else:
            print(colored("UPDATE PARTIAL", 'yellow', attrs=['bold']))
            print(f"{colored(f'{success_count}/{len(downloads)} databases updated successfully.', 'yellow')}\n")

        print(colored("╚══════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))
        print(f"{colored('💡 Tip:', 'blue')} Wordlists saved to data/ directory\n")
