"""Configuration constants for CyberGuardian Ultimate"""

VERSION = '2.0'

CONFIG = {
    'cve_db_url': 'https://cve.mitre.org/data/downloads/allitems.csv',
    'dir_list_url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt',
    'subdomain_list_url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
    'exploit_db_csv_url': 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv',
    'exploit_db_api': 'https://exploit-db.com/search',
    'github_repo': 'https://github.com/NikolisSecurity/CyberToolX.git',
    'update_check_interval': 3600,
    'banner_color': 'red',        # Neon red theme (#ff0055)
    'highlight_color': 'red',     # Neon red for highlights
    'critical_color': 'red',      # Neon red for critical items
    'success_color': 'green',     # Neon green (#00ff88)
    'warning_color': 'yellow',    # Neon orange (#ffaa00)
    'max_threads': 50,
    'timeout': 5,
    'user_agent': 'CyberGuardian/2.0',
}

# Default configuration values
DEFAULTS = {
    'default_mode': 'fast',
    'timeout': 5,
    'threads': 50,
    'delay': 0,
    'verify_ssl': False,
    'follow_redirects': False,
    'enable_subdomains': True,
    'enable_directory_enum': True,
    'enable_exploit_lookup': True,
    'enable_ssl_analysis': True,
    'default_output_format': 'html',
    'verbose': False,
}
