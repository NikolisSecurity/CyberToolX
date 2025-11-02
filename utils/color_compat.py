"""Termcolor compatibility module with neon cyberpunk theme - fallback to ANSI codes if termcolor unavailable"""

try:
    from termcolor import colored as _termcolor_colored
    HAS_TERMCOLOR = True

    # Enhanced neon cyberpunk color mapping for termcolor
    # Maps standard color names to neon theme equivalents with new accent colors
    COLOR_MAP = {
        # Original mappings
        'cyan': 'red',      # cyan → neon red (#ff0055)
        'red': 'red',       # red → neon red (#ff0055)
        'green': 'green',   # green → neon green (#00ff88)
        'yellow': 'yellow', # yellow → neon orange (#ffaa00)
        'blue': 'magenta',  # blue → lighter pink-red (#ff3377, closest to magenta)
        'magenta': 'magenta',  # magenta → lighter pink-red
        'white': 'white',   # white stays white
        'grey': 'white',    # grey → white for better visibility

        # New accent color mappings
        'tech_cyan': 'cyan',       # Tech cyan for data streams
        'cyber_purple': 'magenta', # Cyber purple for special effects
        'bright_white': 'white',   # Bright white for highlights
        'enhanced_green': 'green', # Enhanced green for success states
        'electric_blue': 'blue',   # Electric blue for network connections
        'neon_pink': 'magenta',    # Neon pink for special highlights
        'acid_green': 'green',     # Acid green for alerts
        'deep_purple': 'magenta',  # Deep purple for background elements
    }

    def colored(text, color=None, on_color=None, attrs=None):
        """Enhanced colored function with neon theme and bold by default"""
        # Map color to neon theme
        if color:
            color = COLOR_MAP.get(color, color)

        # Add bold by default for glow effect
        if attrs is None:
            attrs = ['bold']
        elif 'bold' not in attrs:
            attrs = list(attrs) + ['bold']

        return _termcolor_colored(text, color, on_color, attrs)

except ImportError:
    HAS_TERMCOLOR = False

    # Enhanced ANSI color codes fallback (bright colors for neon effect)
    COLORS = {
        # Original colors
        'red': '\033[91m',      # Bright red (neon red)
        'green': '\033[92m',    # Bright green (neon green)
        'yellow': '\033[93m',   # Bright yellow (neon orange)
        'blue': '\033[95m',     # Bright magenta (lighter pink-red)
        'magenta': '\033[95m',  # Bright magenta (lighter pink-red)
        'cyan': '\033[96m',     # Bright cyan
        'white': '\033[97m',    # Bright white
        'grey': '\033[97m',     # Map grey to bright white

        # New accent colors with ANSI codes
        'tech_cyan': '\033[96m',      # Bright cyan for tech elements
        'cyber_purple': '\033[95m',   # Bright magenta for cyber symbols
        'bright_white': '\033[97m',   # Bright white for highlights
        'enhanced_green': '\033[92m', # Bright green for success
        'electric_blue': '\033[94m',  # Bright blue for network
        'neon_pink': '\033[95m',      # Bright magenta for highlights
        'acid_green': '\033[92m',     # Bright green for alerts
        'deep_purple': '\033[35m',    # Standard magenta for backgrounds
    }

    ATTRS = {
        'bold': '\033[1m',
        'underline': '\033[4m',
        'blink': '\033[5m',
    }

    RESET = '\033[0m'

    def colored(text, color=None, on_color=None, attrs=None):
        """Fallback colored function using ANSI codes with bold by default"""
        result = ''

        # Add bold by default for glow effect
        if attrs is None:
            attrs = ['bold']
        elif 'bold' not in attrs:
            attrs = list(attrs) + ['bold']

        if attrs:
            for attr in attrs:
                result += ATTRS.get(attr, '')

        if color:
            result += COLORS.get(color, '')

        result += str(text) + RESET
        return result


# Enhanced theme support functions
def get_theme_colors(theme_name: str = 'default'):
    """Get a coordinated color set for a specific theme"""
    try:
        import sys
        import os
        # Import config to access color themes
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from config import COLOR_THEMES, COLOR_PALETTE

        theme = COLOR_THEMES.get(theme_name, COLOR_THEMES['default'])
        return theme
    except (ImportError, KeyError):
        # Fallback to basic theme if config is unavailable
        return {
            'primary': 'red',
            'success': 'green',
            'warning': 'yellow',
            'accent': 'magenta',
            'tech': 'cyan',
            'special': 'magenta',
            'highlight': 'white',
            'secondary': 'green'
        }


def apply_terminal_theme(theme_name: str = 'default'):
    """Apply a color theme globally for terminal output"""
    theme_colors = get_theme_colors(theme_name)

    # Store current theme globally
    if not hasattr(apply_terminal_theme, 'current_theme'):
        apply_terminal_theme.current_theme = 'default'

    apply_terminal_theme.current_theme = theme_name
    return theme_colors


def get_current_theme():
    """Get the currently active theme"""
    return getattr(apply_terminal_theme, 'current_theme', 'default')


def color_animation(text: str, colors: list = None, duration: float = 2.0):
    """Apply simple color cycling effect to text"""
    if colors is None:
        # Use theme colors for animation
        theme = get_theme_colors()
        colors = ['red', 'yellow', 'green', 'cyan', 'magenta']

    # For immediate display, return text with first color
    # In a real-time animation context, this would cycle through colors
    return colored(text, colors[0] if colors else 'white')


def themed_colored(text: str, color_role: str, theme_name: str = None):
    """Apply color based on theme role (primary, success, warning, etc.)"""
    if theme_name is None:
        theme_name = get_current_theme()

    theme_colors = get_theme_colors(theme_name)
    actual_color = theme_colors.get(color_role, 'white')

    return colored(text, actual_color)


def get_available_themes():
    """Get list of available color themes"""
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from config import COLOR_THEMES
        return list(COLOR_THEMES.keys())
    except ImportError:
        return ['default']


def validate_color_support():
    """Check what level of color support the terminal has"""
    import os

    # Check for common color support indicators
    colorterm = os.environ.get('COLORTERM', '').lower()
    term = os.environ.get('TERM', '').lower()

    if colorterm in ['truecolor', '24bit']:
        return 'truecolor'
    elif '256' in term:
        return '256color'
    elif any(color_term in term for color_term in ['xterm', 'screen', 'ansi']):
        return 'basic'
    else:
        return 'none'


def get_fallback_color_mapping():
    """Get a mapping of theme colors to basic terminal colors for fallback"""
    return {
        'primary_red': 'red',
        'success_green': 'green',
        'warning_orange': 'yellow',
        'accent_magenta': 'magenta',
        'tech_cyan': 'cyan',
        'cyber_purple': 'magenta',
        'bright_white': 'white',
        'enhanced_green': 'green',
        'electric_blue': 'blue',
        'neon_pink': 'magenta',
        'acid_green': 'green',
        'deep_purple': 'magenta'
    }
