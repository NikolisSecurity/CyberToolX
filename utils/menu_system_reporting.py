# Reporting methods to be added to MenuSystem class

def generate_report(self):
    """Generate comprehensive HTML/JSON report from scan results"""
    if not self.scan_results:
        AsciiArt.error_message("No scan results to report. Run some scans first!")
        return

    print(colored("\n╔═══════════════════════ GENERATING REPORT ════════════════════════╗\n", 'red', attrs=['bold']))

    from pathlib import Path
    from datetime import datetime

    # Create reports directory
    reports_dir = Path(__file__).parent.parent / 'reports'
    reports_dir.mkdir(exist_ok=True)

    # Generate timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = reports_dir / f'report_{timestamp}.html'

    print(f"{colored('Collecting scan results...', 'yellow')}")

    # Count findings
    total_findings = sum(len(v) if isinstance(v, (list, dict)) else 1 for v in self.scan_results.values() if v)

    for scan_type, results in self.scan_results.items():
        if results:
            count = len(results) if isinstance(results, (list, dict)) else 1
            print(f"{colored('✓', 'green')} {scan_type}: {count} findings")

    print(f"\n{colored('Generating HTML report...', 'yellow')}\n")

    # Build HTML report with neon theme
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>NPS Tool Security Report - {self.current_target}</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            padding: 30px;
            background: #000000;
            color: #ff3377;
            line-height: 1.6;
        }}
        h1 {{
            color: #ff0055;
            text-shadow: 0 0 10px rgba(255, 0, 85, 0.5);
            border: 2px solid #ff0055;
            padding: 15px;
            box-shadow: 0 0 20px rgba(255, 0, 85, 0.3);
            background: #0a0000;
            text-align: center;
        }}
        h2 {{
            color: #ff0055;
            text-shadow: 0 0 8px rgba(255, 0, 85, 0.4);
            border-left: 4px solid #ff0055;
            padding-left: 10px;
            margin-top: 30px;
        }}
        .metadata {{
            background: #0a0000;
            border: 2px solid #ff0055;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 0 15px rgba(255, 0, 85, 0.2);
        }}
        .scan-section {{
            background: #0a0000;
            border-left: 3px solid #ff0055;
            padding: 15px;
            margin: 20px 0;
        }}
        pre {{
            background: #0a0a0a;
            border: 1px solid #ff0055;
            padding: 10px;
            overflow-x: auto;
            color: #ff3377;
        }}
    </style>
</head>
<body>
    <h1>🔒 NPS Tool Security Report</h1>
    <div class="metadata">
        <p><strong>Target:</strong> {self.current_target or 'N/A'}</p>
        <p><strong>Report Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Total Scans:</strong> {len(self.scan_results)}</p>
    </div>
"""

    # Add each scan result
    import json
    for scan_type, results in self.scan_results.items():
        if results:
            html_content += f"""    <div class="scan-section">
        <h2>📊 {scan_type.upper()}</h2>
        <pre>{json.dumps(results, indent=2, default=str)}</pre>
    </div>
"""

    html_content += """</body>
</html>
"""

    # Write report
    report_file.write_text(html_content)

    print(colored("╚══════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))
    AsciiArt.success_message(f"Report created: {report_file}")
    print(f"{colored('💡 Tip:', 'blue')} Open report in browser\n")

    return str(report_file)


def export_results(self, args):
    """Export scan results to file"""
    if not self.scan_results:
        AsciiArt.error_message("No scan results to export.")
        return

    from pathlib import Path
    from datetime import datetime
    import json

    format_type = args[0].lower() if args else 'json'
    if format_type not in ['json', 'csv', 'txt']:
        format_type = 'json'

    exports_dir = Path(__file__).parent.parent / 'exports'
    exports_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'scan_export_{timestamp}.{format_type}'
    export_file = exports_dir / filename

    with open(export_file, 'w') as f:
        json.dump({'target': self.current_target, 'results': self.scan_results}, f, indent=2, default=str)

    AsciiArt.success_message(f"Exported to: {export_file}")


def show_history(self):
    """View scan history"""
    print(colored("\n╔═══════════════════════ SCAN HISTORY ═════════════════════════════╗\n", 'red', attrs=['bold']))
    if not self.scan_history:
        print(f"{colored('No scan history yet.', 'white')}\n")
    else:
        for i, entry in enumerate(self.scan_history[-10:][::-1], 1):
            print(f"{i}. {entry}")
    print(colored("╚══════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))


def compare_results(self, args):
    """Compare scan results"""
    print(colored("\n╔═══════════════════════ SCAN COMPARISON ══════════════════════════╗\n", 'red', attrs=['bold']))
    print(f"{colored('Comparison feature - showing current results', 'yellow')}\n")
    if self.scan_results:
        for scan_type in self.scan_results.keys():
            print(f"  • {scan_type}")
    print(colored("\n╚══════════════════════════════════════════════════════════════════╝\n", 'red', attrs=['bold']))
