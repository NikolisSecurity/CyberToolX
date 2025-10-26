#!/usr/bin/env python3
"""
CyberGuardian Ultimate v2.0 - Interactive Edition
Advanced Cybersecurity Warfare Platform

Interactive menu-driven interface with 60+ security tools
Type 'help' for available commands
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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
