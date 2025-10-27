#!/usr/bin/env python3
"""
NPS Tool v1.0 - Web Security Edition
Network Pentesting Suite

Interactive menu-driven interface for web security testing
Type 'help' for available commands
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Add system site-packages to path to access installed modules
sys.path.append('/usr/local/lib/python3.12/site-packages')

from utils.menu_system import MenuSystem


def main():
    """Launch CyberGuardian Ultimate interactive interface"""
    try:
        menu = MenuSystem()
        menu.run()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        sys.exit(0)
    except Exception as e:
        print(f"\nFatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
