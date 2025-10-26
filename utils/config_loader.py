"""Configuration file loader with YAML support"""

import os
import yaml
from pathlib import Path
from config import DEFAULTS


class ConfigLoader:
    """Loads and merges configuration from YAML files"""

    @staticmethod
    def load_config():
        """
        Load configuration from YAML files.

        Priority:
        1. ./config.yaml (local directory)
        2. ~/.cyberguardian/config.yaml (user home)
        3. DEFAULTS (fallback)

        Returns:
            dict: Merged configuration
        """
        config = DEFAULTS.copy()

        # Check for user config
        user_config_path = Path.home() / '.cyberguardian' / 'config.yaml'
        if user_config_path.exists():
            try:
                with open(user_config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        config.update(user_config)
            except Exception as e:
                from utils.printer import Printer
                Printer.warning(f"Failed to load user config: {str(e)}")

        # Check for local config (higher priority)
        local_config_path = Path('config.yaml')
        if local_config_path.exists():
            try:
                with open(local_config_path, 'r') as f:
                    local_config = yaml.safe_load(f)
                    if local_config:
                        config.update(local_config)
            except Exception as e:
                from utils.printer import Printer
                Printer.error(f"Failed to load local config: {str(e)}")
                raise SystemExit(1)

        return config

    @staticmethod
    def create_default_config(path='config.yaml'):
        """Create default configuration file"""
        default_config = """# CyberGuardian Ultimate Configuration
# All settings here can be overridden by command-line arguments

# Scan settings
default_mode: fast
timeout: 5
threads: 50
delay: 0
user_agent: "CyberGuardian/2.0"

# Feature toggles
enable_subdomains: true
enable_directory_enum: true
enable_exploit_lookup: true
enable_ssl_analysis: true

# Wordlists (optional custom paths)
# directory_wordlist: "path/to/wordlist.txt"
# subdomain_wordlist: "path/to/subdomains.txt"

# Output
default_output_format: html
verbose: false

# Network
# proxy: null
verify_ssl: false
follow_redirects: false
"""

        try:
            with open(path, 'w') as f:
                f.write(default_config)
            from utils.printer import Printer
            Printer.success(f"Created config file: {path}")
            return True
        except Exception as e:
            from utils.printer import Printer
            Printer.error(f"Failed to create config file: {str(e)}")
            return False
