"""Terminal detection and responsive layout management for enhanced CLI experience"""

import os
import sys
import shutil
from enum import Enum
from typing import Tuple, Dict, Optional


class TerminalSize(Enum):
    """Terminal size presets for responsive design"""
    SMALL = "small"      # <80x24
    MEDIUM = "medium"    # 80x24 to 120x30
    LARGE = "large"      # >120x30


class TerminalDetector:
    """Detect terminal capabilities and determine optimal layout preset"""

    def __init__(self):
        self._cached_size = None
        self._cached_capabilities = None

    def get_terminal_size(self) -> Tuple[int, int]:
        """Get current terminal dimensions (width, height)"""
        try:
            size = shutil.get_terminal_size()
            return size.columns, size.lines
        except (OSError, AttributeError):
            # Fallback for environments where get_terminal_size fails
            try:
                # Try using stty on Unix-like systems
                import subprocess
                result = subprocess.run(['stty', 'size'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines, columns = result.stdout.strip().split()
                    return int(columns), int(lines)
            except (OSError, subprocess.SubprocessError, ValueError):
                pass

            # Ultimate fallback defaults
            return 80, 24

    def determine_preset(self) -> TerminalSize:
        """Determine which size preset to use based on terminal dimensions"""
        width, height = self.get_terminal_size()

        if width < 80 or height < 24:
            return TerminalSize.SMALL
        elif width <= 120 and height <= 30:
            return TerminalSize.MEDIUM
        else:
            return TerminalSize.LARGE

    def supports_unicode(self) -> bool:
        """Check if terminal supports Unicode characters"""
        # Common Unicode-supporting environment variables
        if os.environ.get('LANG', '').lower().endswith('utf-8'):
            return True

        # Check common terminal emulators known to support Unicode
        term = os.environ.get('TERM', '').lower()
        unicode_terms = ['xterm', 'screen', 'tmux', 'alacritty', 'kitty', 'iterm', 'gnome', 'konsole']
        return any(uni_term in term for uni_term in unicode_terms)

    def supports_color(self) -> int:
        """Check terminal color support level (0=none, 1=basic, 2=256, 3=truecolor)"""
        # Check COLORTERM environment variable
        colorterm = os.environ.get('COLORTERM', '').lower()
        if colorterm in ['truecolor', '24bit']:
            return 3

        # Check TERM environment variable
        term = os.environ.get('TERM', '').lower()
        if '256' in term:
            return 2
        elif any(color_term in term for color_term in ['xterm', 'screen', 'ansi']):
            return 1

        # Check if we're running in a common IDE terminal that supports colors
        if os.environ.get('VS_CODE') or os.environ.get('PYCHARM'):
            return 2

        return 0  # No color support detected

    def get_capabilities(self) -> Dict[str, any]:
        """Get all terminal capabilities in a single dictionary"""
        if self._cached_capabilities is None:
            self._cached_capabilities = {
                'size': self.get_terminal_size(),
                'preset': self.determine_preset(),
                'unicode': self.supports_unicode(),
                'color_level': self.supports_color(),
                'is_windows': os.name == 'nt',
                'is_tty': sys.stdout.isatty()
            }
        return self._cached_capabilities

    def refresh_capabilities(self):
        """Refresh cached capabilities - call when terminal might have changed"""
        self._cached_capabilities = None
        self._cached_size = None


class LayoutEngine:
    """Calculate optimal panel dimensions for different terminal sizes"""

    def __init__(self, terminal_detector: TerminalDetector):
        self.detector = terminal_detector
        self._preset_configs = {
            TerminalSize.SMALL: {
                'banner_width': 50,
                'show_sidebar': False,
                'show_status_bar': False,
                'padding': 1,
                'panel_separator': '═'
            },
            TerminalSize.MEDIUM: {
                'banner_width': 70,
                'show_sidebar': True,
                'show_status_bar': True,
                'sidebar_width': 25,
                'padding': 2,
                'panel_separator': '═'
            },
            TerminalSize.LARGE: {
                'banner_width': 100,
                'show_sidebar': True,
                'show_status_bar': True,
                'sidebar_width': 30,
                'padding': 3,
                'panel_separator': '═'
            }
        }

    def get_config(self) -> Dict[str, any]:
        """Get layout configuration for current terminal size"""
        preset = self.detector.determine_preset()
        config = self._preset_configs[preset].copy()

        # Get actual terminal dimensions
        width, height = self.detector.get_terminal_size()

        # Adjust banner width to fit terminal
        max_banner_width = width - 4  # Leave room for borders
        if config['banner_width'] > max_banner_width:
            config['banner_width'] = max(max_banner_width, 40)  # Minimum width

        # Adjust sidebar width for medium terminals if needed
        if preset == TerminalSize.MEDIUM and width < 100:
            config['sidebar_width'] = 20
        elif preset == TerminalSize.LARGE and width < 140:
            config['sidebar_width'] = 25

        return config

    def calculate_dimensions(self) -> Dict[str, any]:
        """Calculate exact panel dimensions for current terminal"""
        width, height = self.detector.get_terminal_size()
        config = self.get_config()

        dimensions = {
            'terminal_width': width,
            'terminal_height': height,
            'preset': self.detector.determine_preset().value
        }

        # Header panel (banner)
        dimensions['header_height'] = 8 if config['show_sidebar'] else 6
        dimensions['header_width'] = config['banner_width']
        dimensions['header_x'] = max(1, (width - config['banner_width']) // 2)
        dimensions['header_y'] = 1

        if config['show_sidebar']:
            # Sidebar panel
            dimensions['sidebar_width'] = config['sidebar_width']
            dimensions['sidebar_height'] = height - dimensions['header_height'] - (3 if config['show_status_bar'] else 2)
            dimensions['sidebar_x'] = 1
            dimensions['sidebar_y'] = dimensions['header_height'] + 1

            # Main panel (content)
            dimensions['main_width'] = width - config['sidebar_width'] - 3  # Account for borders
            dimensions['main_height'] = dimensions['sidebar_height']
            dimensions['main_x'] = config['sidebar_width'] + 2
            dimensions['main_y'] = dimensions['header_height'] + 1
        else:
            # Main panel takes full width (minus borders)
            dimensions['main_width'] = width - 2
            dimensions['main_height'] = height - dimensions['header_height'] - (3 if config['show_status_bar'] else 2)
            dimensions['main_x'] = 1
            dimensions['main_y'] = dimensions['header_height'] + 1

        if config['show_status_bar']:
            # Status bar at bottom
            dimensions['status_height'] = 2
            dimensions['status_width'] = width - 2
            dimensions['status_x'] = 1
            dimensions['status_y'] = height - 2

        return dimensions

    def position_elements(self) -> Dict[str, Dict[str, int]]:
        """Calculate exact positioning coordinates for dashboard elements"""
        dimensions = self.calculate_dimensions()
        positions = {}

        # Header positioning
        positions['header'] = {
            'x': dimensions['header_x'],
            'y': dimensions['header_y'],
            'width': dimensions['header_width'],
            'height': dimensions['header_height']
        }

        # Main content positioning
        positions['main'] = {
            'x': dimensions['main_x'],
            'y': dimensions['main_y'],
            'width': dimensions['main_width'],
            'height': dimensions['main_height']
        }

        # Sidebar positioning (if enabled)
        if 'sidebar_x' in dimensions:
            positions['sidebar'] = {
                'x': dimensions['sidebar_x'],
                'y': dimensions['sidebar_y'],
                'width': dimensions['sidebar_width'],
                'height': dimensions['sidebar_height']
            }

        # Status bar positioning (if enabled)
        if 'status_x' in dimensions:
            positions['status'] = {
                'x': dimensions['status_x'],
                'y': dimensions['status_y'],
                'width': dimensions['status_width'],
                'height': dimensions['status_height']
            }

        return positions

    def format_for_terminal(self, text: str, panel: str = 'main', align: str = 'left') -> str:
        """Format text to fit within panel dimensions"""
        positions = self.position_elements()
        panel_info = positions.get(panel, positions['main'])
        panel_width = panel_info['width'] - 2  # Account for borders

        if align == 'center':
            return text.center(panel_width)
        elif align == 'right':
            return text.rjust(panel_width)
        else:  # left align
            return text.ljust(panel_width)

    def get_separator_chars(self) -> Dict[str, str]:
        """Get appropriate border characters based on terminal capabilities"""
        config = self.get_config()
        supports_unicode = self.detector.supports_unicode()

        if supports_unicode:
            return {
                'horizontal': '═',
                'vertical': '║',
                'top_left': '╔',
                'top_right': '╗',
                'bottom_left': '╚',
                'bottom_right': '╝',
                'cross': '╬',
                't_down': '╦',
                't_up': '╩',
                't_right': '╠',
                't_left': '╣'
            }
        else:
            # Fallback to basic ASCII for terminals without Unicode support
            return {
                'horizontal': '-',
                'vertical': '|',
                'top_left': '+',
                'top_right': '+',
                'bottom_left': '+',
                'bottom_right': '+',
                'cross': '+',
                't_down': '+',
                't_up': '+',
                't_right': '+',
                't_left': '+'
            }


# Convenience functions for easy access
def create_terminal_detector() -> TerminalDetector:
    """Create a new TerminalDetector instance"""
    return TerminalDetector()


def create_layout_engine(detector: TerminalDetector = None) -> LayoutEngine:
    """Create a new LayoutEngine instance"""
    if detector is None:
        detector = TerminalDetector()
    return LayoutEngine(detector)


def get_terminal_info() -> Dict[str, any]:
    """Get complete terminal information in one call"""
    detector = TerminalDetector()
    engine = LayoutEngine(detector)

    return {
        'capabilities': detector.get_capabilities(),
        'layout_config': engine.get_config(),
        'dimensions': engine.calculate_dimensions(),
        'positions': engine.position_elements(),
        'separators': engine.get_separator_chars()
    }