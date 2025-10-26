"""Termcolor compatibility module - fallback to ANSI codes if termcolor unavailable"""

try:
    from termcolor import colored
    HAS_TERMCOLOR = True
except ImportError:
    HAS_TERMCOLOR = False

    # ANSI color codes fallback
    COLORS = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'grey': '\033[90m',
    }

    ATTRS = {
        'bold': '\033[1m',
        'underline': '\033[4m',
        'blink': '\033[5m',
    }

    RESET = '\033[0m'

    def colored(text, color=None, on_color=None, attrs=None):
        """Fallback colored function using ANSI codes"""
        result = ''

        if attrs:
            for attr in attrs:
                result += ATTRS.get(attr, '')

        if color:
            result += COLORS.get(color, '')

        result += str(text) + RESET
        return result
