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

# Enhanced color palette with accent colors
COLOR_PALETTE = {
    # Primary colors (keep current focus)
    'primary_red': '#ff0055',     # Neon red - main banners and critical elements
    'success_green': '#00ff88',   # Neon green - success states
    'warning_orange': '#ffaa00',  # Neon orange - warnings
    'accent_magenta': '#ff3377',  # Pink-red/magenta - secondary highlights

    # New accent colors
    'tech_cyan': '#00ffff',       # Tech cyan - data streams and tech elements
    'cyber_purple': '#9933ff',    # Cyber purple - cyber symbols and special effects
    'bright_white': '#ffffff',    # Bright white - highlights and critical text
    'enhanced_green': '#00cc44',  # Enhanced green - improved success states

    # Additional themed colors
    'electric_blue': '#0099ff',   # Electric blue - network connections
    'neon_pink': '#ff0099',       # Neon pink - special highlights
    'acid_green': '#99ff00',      # Acid green - alerts
    'deep_purple': '#6600cc',     # Deep purple - background elements
}

# Color themes for different moods/purposes
COLOR_THEMES = {
    'default': {
        'primary': 'primary_red',
        'success': 'success_green',
        'warning': 'warning_orange',
        'accent': 'accent_magenta',
        'tech': 'tech_cyan',
        'special': 'cyber_purple',
        'highlight': 'bright_white',
        'secondary': 'enhanced_green'
    },
    'stealth': {
        'primary': 'deep_purple',
        'success': 'enhanced_green',
        'warning': 'electric_blue',
        'accent': 'tech_cyan',
        'tech': 'neon_pink',
        'special': 'cyber_purple',
        'highlight': 'bright_white',
        'secondary': 'accent_magenta'
    },
    'aggressive': {
        'primary': 'neon_pink',
        'success': 'acid_green',
        'warning': 'primary_red',
        'accent': 'cyber_purple',
        'tech': 'electric_blue',
        'special': 'tech_cyan',
        'highlight': 'bright_white',
        'secondary': 'warning_orange'
    },
    'professional': {
        'primary': 'primary_red',
        'success': 'enhanced_green',
        'warning': 'warning_orange',
        'accent': 'electric_blue',
        'tech': 'tech_cyan',
        'special': 'cyber_purple',
        'highlight': 'bright_white',
        'secondary': 'accent_magenta'
    }
}

# Terminal presets for responsive design
TERMINAL_PRESETS = {
    'small': {
        'banner_width': 50,
        'show_sidebar': False,
        'show_status_bar': False,
        'padding': 1,
        'max_content_lines': 10,
        'compact_mode': True,
        'minimal_animations': True
    },
    'medium': {
        'banner_width': 70,
        'show_sidebar': True,
        'show_status_bar': True,
        'sidebar_width': 25,
        'padding': 2,
        'max_content_lines': 20,
        'compact_mode': False,
        'minimal_animations': False
    },
    'large': {
        'banner_width': 100,
        'show_sidebar': True,
        'show_status_bar': True,
        'sidebar_width': 30,
        'padding': 3,
        'max_content_lines': 50,
        'compact_mode': False,
        'minimal_animations': False,
        'enhanced_graphics': True
    }
}

# Animation settings
ANIMATION_SETTINGS = {
    'enabled': True,
    'speed': 0.1,           # Base animation speed in seconds
    'max_fps': 10,          # Maximum frames per second
    'interruptible': True,  # Can animations be interrupted
    'color_cycling': True,  # Enable color transitions
    'progress_smoothness': 0.05,  # Progress bar update interval
    'loading_timeout': 30,   # Maximum loading animation time
    'minimal_mode': False   # Force minimal animations
}

# Cyber-themed symbols and characters
CYBER_SYMBOLS = {
    'circuit': ['├─┤', '╔═╗', '●─●', '⚡', '⟐', '◀▶'],
    'security': ['🔒', '🔐', '🛡️', '🔬', '🔍', '📡'],
    'data': ['⬛', '⬜', '▪', '▫', '◆', '◇'],
    'status': ['●', '○', '◐', '◑', '◉', '⟳'],
    'arrows': ['◀', '▶', '▲', '▼', '◄', '►'],
    'tech': ['⚡', '⟐', '◈', '⬡', '⬢', '⬠']
}

# ASCII art styles
ASCII_ART_STYLES = {
    'circuit_board': {
        'border_chars': '═║╔╗╚╝╦╩╠╣╬',
        'connection_chars': '─│┌┐└┘├┤┬┴┼',
        'node_chars': '●○◐◑◉',
        'flow_chars': '⚡⟐◀▶'
    },
    'security_lock': {
        'border_chars': '═║╔╗╚╝',
        'lock_chars': '🔒🔐🛡️',
        'shield_chars': '🛡️⛨',
        'key_chars': '🔑🗝️'
    },
    'data_stream': {
        'border_chars': '═║╔╗╚╝',
        'flow_chars': '⬛⬜▪▫◆◇',
        'arrow_chars': '◀▶▲▼◄►',
        'data_chars': '⟐◈⬡⬢⬠'
    }
}

# Dashboard configuration
DASHBOARD_CONFIG = {
    'refresh_rate': 1.0,       # Dashboard refresh interval in seconds
    'auto_scroll': True,       # Auto-scroll content area
    'max_history': 1000,       # Maximum lines in content history
    'show_timestamps': True,   # Show timestamps in content
    'persistent_layout': True, # Remember layout between sessions
    'responsive': True,        # Enable responsive design
    'animations_enabled': True # Enable dashboard animations
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
