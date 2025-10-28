"""Termcolor compatibility module with neon cyberpunk theme - fallback to ANSI codes if termcolor unavailable"""

try:
    from termcolor import colored as _termcolor_colored
    HAS_TERMCOLOR = True

    # Neon cyberpunk color mapping for termcolor
    # Maps standard color names to neon theme equivalents
    COLOR_MAP = {
        'cyan': 'red',      # cyan → neon red (#ff0055)
        'red': 'red',       # red → neon red (#ff0055)
        'green': 'green',   # green → neon green (#00ff88)
        'yellow': 'yellow', # yellow → neon orange (#ffaa00)
        'blue': 'magenta',  # blue → lighter pink-red (#ff3377, closest to magenta)
        'magenta': 'magenta',  # magenta → lighter pink-red
        'white': 'white',   # white stays white
        'grey': 'white',    # grey → white for better visibility
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

    # ANSI color codes fallback (bright colors for neon effect)
    COLORS = {
        'red': '\033[91m',      # Bright red (neon red)
        'green': '\033[92m',    # Bright green (neon green)
        'yellow': '\033[93m',   # Bright yellow (neon orange)
        'blue': '\033[95m',     # Bright magenta (lighter pink-red)
        'magenta': '\033[95m',  # Bright magenta (lighter pink-red)
        'cyan': '\033[91m',     # Map cyan to bright red (neon red)
        'white': '\033[97m',    # Bright white
        'grey': '\033[97m',     # Map grey to bright white
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
