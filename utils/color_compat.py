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
