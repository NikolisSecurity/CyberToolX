"""Formatted console output utility"""

from termcolor import colored


class Printer:
    """Handles formatted console output with color coding"""

    @staticmethod
    def _format(message, level, color, attrs=None):
        """Format message with colored borders"""
        border = colored('═' * (len(message) + 4), color)
        return f"{border}\n  {colored(level, color, attrs=attrs)} {message}\n{border}"

    @staticmethod
    def status(message):
        """Print status message (blue)"""
        print(colored(f"[►] {message}", 'blue'))

    @staticmethod
    def success(message):
        """Print success message (green with border)"""
        print(Printer._format(message, "SUCCESS", 'green'))

    @staticmethod
    def warning(message):
        """Print warning message (yellow with border)"""
        print(Printer._format(message, "WARNING", 'yellow'))

    @staticmethod
    def error(message):
        """Print error message (red with border)"""
        print(Printer._format(message, "ERROR", 'red'))

    @staticmethod
    def critical(message):
        """Print critical message (bold red with border)"""
        print(Printer._format(message, "CRITICAL", 'red', ['bold']))
