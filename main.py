#!/usr/bin/env python3
"""
CyberGuardian Ultimate v2.0
Advanced Cybersecurity Scanning Platform

Usage:
    python3 main.py <target> [options]

For detailed help:
    python3 main.py --help
"""

import argparse
import sys
import os

from config import VERSION
from utils import SecurityArt, Printer
from updater import GitHubUpdater
from core import CyberSentinel


def main():
    """Main entry point for CyberGuardian Ultimate"""
    print(SecurityArt.banner(VERSION))

    # Check for updates first
    if GitHubUpdater.check_update():
        sys.exit(0)

    # Create scanner instance
    scanner = CyberSentinel()

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="CyberGuardian Ultimate - Enterprise Cybersecurity Platform",
        epilog="For detailed documentation, see README.md"
    )

    parser.add_argument("target", help="Target IP/URL to scan")
    parser.add_argument("-m", "--mode", choices=['fast', 'deep'], default='fast',
                       help="Scanning intensity level (default: fast)")
    parser.add_argument("-o", "--output", choices=['html', 'json'], default='html',
                       help="Report output format (default: html)")
    parser.add_argument("-u", "--update", action="store_true",
                       help="Force update check and exit")
    parser.add_argument("--version", action="version", version=f"CyberGuardian Ultimate v{VERSION}")

    args = parser.parse_args()

    if args.update:
        GitHubUpdater.check_update()
        return

    try:
        # Execute scan
        scanner.scan_target(args.target, args.mode)

        # Generate report
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
