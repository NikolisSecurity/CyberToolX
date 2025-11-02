"""Multi-panel dashboard rendering engine for enhanced CLI interface"""

import sys
import os
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from datetime import datetime

from .color_compat import colored
from .terminal_utils import LayoutEngine, TerminalDetector
from .animation_engine import AnimationController, AnimationState


@dataclass
class PanelContent:
    """Content structure for dashboard panels"""
    title: str
    content: List[str]
    color: str = 'white'
    border_color: str = 'red'
    update_interval: float = 1.0  # Seconds between updates
    last_updated: float = 0.0
    dynamic: bool = False  # Content changes over time
    update_callback: Optional[Callable] = None


class DashboardRenderer:
    """Multi-panel dashboard rendering engine with responsive design"""

    def __init__(self, layout_engine: Optional[LayoutEngine] = None):
        self.layout_engine = layout_engine or LayoutEngine(TerminalDetector())
        self.animation_controller = AnimationController()

        # Panel content registry
        self.panels = {
            'header': None,
            'sidebar': None,
            'main': None,
            'status': None
        }

        # Dashboard state
        self.active = False
        self.clear_screen_on_refresh = True
        self.last_render = {}
        self.animation_state = AnimationState.STOPPED

        # Pre-rendered content cache
        self._render_cache = {}
        self._cache_valid = False

    def register_panel(self, panel_name: str, content: PanelContent) -> None:
        """Register content for a specific panel"""
        if panel_name in self.panels:
            self.panels[panel_name] = content
            self._cache_valid = False

    def render_header(self, title: str = "NPS TOOL", subtitle: str = "Network Pentesting Suite") -> str:
        """Render the top header panel with ASCII art and title"""
        positions = self.layout_engine.position_elements()
        if 'header' not in positions:
            return ""

        header_info = positions['header']
        width = header_info['width']
        height = header_info['height']
        separators = self.layout_engine.get_separator_chars()

        lines = []

        # Top border
        lines.append(separators['top_left'] + separators['horizontal'] * (width - 2) + separators['top_right'])

        # Title line (centered)
        title_line = f" {title} ".center(width - 2)
        lines.append(separators['vertical'] + colored(title_line, 'red', attrs=['bold']) + separators['vertical'])

        # Subtitle line
        subtitle_line = f" {subtitle} ".center(width - 2)
        lines.append(separators['vertical'] + colored(subtitle_line, 'cyan') + separators['vertical'])

        # Empty line
        lines.append(separators['vertical'] + ' ' * (width - 2) + separators['vertical'])

        # Cyber-themed ASCII art line
        if width >= 60:  # Only show ASCII art if there's enough space
            cyber_art = self._get_cyber_art_for_width(width - 4)
            cyber_line = separators['vertical'] + ' ' + cyber_art + ' ' * (width - len(cyber_art) - 3) + separators['vertical']
            lines.append(cyber_line)
        else:
            lines.append(separators['vertical'] + ' ' * (width - 2) + separators['vertical'])

        # Empty line
        lines.append(separators['vertical'] + ' ' * (width - 2) + separators['vertical'])

        # Timestamp line
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        timestamp_line = f" {timestamp} ".rjust(width - 2)
        lines.append(separators['vertical'] + colored(timestamp_line, 'green') + separators['vertical'])

        # Bottom border
        lines.append(separators['bottom_left'] + separators['horizontal'] * (width - 2) + separators['bottom_right'])

        return '\n'.join(lines)

    def render_sidebar(self, target: str = "Not Set", stats: Optional[Dict] = None) -> str:
        """Render the left sidebar panel with real-time information"""
        positions = self.layout_engine.position_elements()
        if 'sidebar' not in positions:
            return ""

        sidebar_info = positions['sidebar']
        width = sidebar_info['width']
        height = sidebar_info['height']
        separators = self.layout_engine.get_separator_chars()

        lines = []

        # Top border
        lines.append(separators['top_left'] + separators['horizontal'] * (width - 2) + separators['top_right'])

        # Title
        title = "SYSTEM INFO"
        title_line = f" {title} ".center(width - 2)
        lines.append(separators['vertical'] + colored(title_line, 'red', attrs=['bold']) + separators['vertical'])

        # Separator
        lines.append(separators['t_right'] + separators['horizontal'] * (width - 2) + separators['vertical'])

        # Target information
        target_label = "Target:"
        target_value = target[:width - len(target_label) - 4] + "..." if len(target) > width - len(target_label) - 4 else target
        target_line = f" {colored(target_label, 'cyan')}{target_value:<{width - len(target_label) - 3}} "
        lines.append(separators['vertical'] + target_line + separators['vertical'])

        # Empty line
        lines.append(separators['vertical'] + ' ' * (width - 2) + separators['vertical'])

        # Stats section
        if stats:
            lines.append(separators['vertical'] + ' ' * (width - 2) + separators['vertical'])

            for key, value in list(stats.items())[:height - 8]:  # Limit to available space
                key_display = str(key)[:width//2 - 2]
                value_display = str(value)[:width//2 - 2]

                stat_line = f" {colored(key_display, 'yellow'):<{width//2 - 1}}{value_display:>{width//2 - 1}} "
                lines.append(separators['vertical'] + stat_line + separators['vertical'])

        # Fill remaining space with empty lines
        current_height = len(lines)
        for _ in range(height - current_height - 1):
            lines.append(separators['vertical'] + ' ' * (width - 2) + separators['vertical'])

        # Bottom border
        lines.append(separators['bottom_left'] + separators['horizontal'] * (width - 2) + separators['bottom_right'])

        return '\n'.join(lines)

    def render_main(self, content: List[str], title: str = "MAIN") -> str:
        """Render the central main panel for command interaction"""
        positions = self.layout_engine.position_elements()
        if 'main' not in positions:
            return ""

        main_info = positions['main']
        width = main_info['width']
        height = main_info['height']
        separators = self.layout_engine.get_separator_chars()

        lines = []

        # Top border
        lines.append(separators['top_left'] + separators['horizontal'] * (width - 2) + separators['top_right'])

        # Title line
        title_line = f" {title} ".center(width - 2)
        lines.append(separators['vertical'] + colored(title_line, 'red', attrs=['bold']) + separators['vertical'])

        # Separator
        lines.append(separators['t_down'] + separators['horizontal'] * (width - 2) + separators['vertical'])

        # Content area
        content_height = height - 4  # Account for borders and title
        for i in range(content_height):
            if i < len(content):
                # Truncate content line if too long
                content_line = content[i]
                if len(content_line) > width - 4:
                    content_line = content_line[:width - 7] + "..."
                line = separators['vertical'] + ' ' + content_line.ljust(width - 4) + ' ' + separators['vertical']
            else:
                line = separators['vertical'] + ' ' * (width - 2) + separators['vertical']
            lines.append(line)

        # Bottom border
        lines.append(separators['bottom_left'] + separators['horizontal'] * (width - 2) + separators['bottom_right'])

        return '\n'.join(lines)

    def render_status_bar(self, notifications: List[str] = None) -> str:
        """Render the bottom status bar with progress and notifications"""
        positions = self.layout_engine.position_elements()
        if 'status' not in positions:
            return ""

        status_info = positions['status']
        width = status_info['width']
        height = status_info['height']
        separators = self.layout_engine.get_separator_chars()

        lines = []

        # Top border (if height > 1)
        if height > 1:
            lines.append(separators['t_left'] + separators['horizontal'] * (width - 2) + separators['t_right'])

        # Status content
        status_parts = []

        # System status
        status_parts.append(colored("●", 'green') + " Ready")

        # Time
        current_time = datetime.now().strftime("%H:%M:%S")
        status_parts.append(colored(current_time, 'cyan'))

        # Notifications (if any)
        if notifications:
            latest_notification = notifications[-1]
            if len(latest_notification) > 30:  # Truncate long notifications
                latest_notification = latest_notification[:27] + "..."
            status_parts.append(colored("⚡", 'yellow') + " " + latest_notification)

        # Build status line
        status_text = " | ".join(status_parts)
        if len(status_text) > width - 4:
            status_text = status_text[:width - 7] + "..."

        status_line = separators['vertical'] + ' ' + status_text.ljust(width - 4) + ' ' + separators['vertical']
        lines.append(status_line)

        # Bottom border
        lines.append(separators['bottom_left'] + separators['horizontal'] * (width - 2) + separators['bottom_right'])

        return '\n'.join(lines)

    def refresh_dashboard(self,
                         header_title: str = "NPS TOOL",
                         sidebar_target: str = "Not Set",
                         sidebar_stats: Optional[Dict] = None,
                         main_content: List[str] = None,
                         status_notifications: List[str] = None,
                         force_clear: bool = True) -> None:
        """Update all panels without clearing entire screen"""
        if not self.active:
            return

        # Clear screen if requested
        if force_clear or self.clear_screen_on_refresh:
            self._clear_screen()

        positions = self.layout_engine.position_elements()
        terminal_width, terminal_height = self.layout_engine.detector.get_terminal_size()

        # Create a buffer for the entire dashboard
        dashboard_buffer = [''] * terminal_height

        # Render each panel and place it in the buffer
        panels_to_render = [
            ('header', lambda: self.render_header(header_title)),
            ('sidebar', lambda: self.render_sidebar(sidebar_target, sidebar_stats)),
            ('main', lambda: self.render_main(main_content or [], "COMMAND OUTPUT")),
            ('status', lambda: self.render_status_bar(status_notifications or []))
        ]

        for panel_name, render_func in panels_to_render:
            if panel_name in positions:
                panel_lines = render_func().split('\n')
                panel_pos = positions[panel_name]

                for i, line in enumerate(panel_lines):
                    y_pos = panel_pos['y'] + i - 1  # Adjust for 0-based indexing
                    if 0 <= y_pos < len(dashboard_buffer):
                        # Insert line at correct horizontal position
                        x_pos = panel_pos['x'] - 1

                        # Ensure buffer line is long enough
                        while len(dashboard_buffer[y_pos]) < x_pos:
                            dashboard_buffer[y_pos] += ' '

                        # Handle panel merging properly
                        if x_pos == 0:
                            # Panel starts at beginning, replace entire line
                            dashboard_buffer[y_pos] = line
                        else:
                            # Panel is positioned after existing content
                            buffer_line = dashboard_buffer[y_pos]
                            if len(buffer_line) >= x_pos:
                                # Overwrite existing content at this position
                                dashboard_buffer[y_pos] = buffer_line[:x_pos] + line
                            else:
                                # Append to buffer line (shouldn't happen with proper layout)
                                dashboard_buffer[y_pos] = buffer_line + ' ' * (x_pos - len(buffer_line)) + line

        # Clear screen and render dashboard
        sys.stdout.write('\033[2J\033[H')  # Clear screen and move cursor to top
        for line in dashboard_buffer:
            if line.strip():  # Only print non-empty lines
                sys.stdout.write(line + '\n')
        sys.stdout.flush()

        self.last_render = {
            'header_title': header_title,
            'sidebar_target': sidebar_target,
            'sidebar_stats': sidebar_stats,
            'main_content': main_content,
            'status_notifications': status_notifications
        }

    def _get_cyber_art_for_width(self, width: int) -> str:
        """Get appropriate cyber-themed ASCII art based on available width"""
        if width >= 80:
            return "⚡ NPS TOOL ⚡ ◈ NETWORK SECURITY ◈"
        elif width >= 60:
            return "⚡ NPS TOOL ◈ SECURITY"
        elif width >= 40:
            return "⚡ NPS ⚡"
        else:
            return "NPS"

    def _clear_screen(self) -> None:
        """Clear the terminal screen"""
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')

    def panel_configurations(self) -> Dict[str, Dict[str, Any]]:
        """Get configuration settings for different layout presets"""
        preset = self.layout_engine.detector.determine_preset()
        config = self.layout_engine.get_config()

        return {
            'preset': preset.value,
            'config': config,
            'panels': {
                'header': {
                    'enabled': True,
                    'height': 8 if config['show_sidebar'] else 6,
                    'animated': True,
                    'refresh_rate': 1.0
                },
                'sidebar': {
                    'enabled': config['show_sidebar'],
                    'width': config.get('sidebar_width', 0),
                    'animated': True,
                    'refresh_rate': 2.0
                },
                'main': {
                    'enabled': True,
                    'auto_scroll': True,
                    'max_lines': 1000
                },
                'status': {
                    'enabled': config['show_status_bar'],
                    'height': 2,
                    'animated': True,
                    'refresh_rate': 0.5
                }
            }
        }

    def panel_animation(self, panel_name: str, animation_type: str = 'fade') -> None:
        """Apply smooth transitions between panel states"""
        if not self.active:
            return

        # Simple fade effect by clearing and re-rendering
        if animation_type == 'fade':
            for i in range(3):
                self.animation_controller._frame_delay()
                # In a full implementation, this would gradually change opacity/brightness
                time.sleep(0.1)

    def responsive_adjustment(self) -> None:
        """Handle terminal size changes"""
        try:
            # Refresh terminal capabilities
            self.layout_engine.detector.refresh_capabilities()

            # Get new positions
            new_positions = self.layout_engine.position_elements()

            # Check if layout significantly changed
            if self._layout_significantly_changed(new_positions):
                # Re-render entire dashboard with new layout
                if self.last_render:
                    self.refresh_dashboard(**self.last_render, force_clear=True)
        except Exception:
            # Silently handle adjustment errors to prevent crashes
            pass

    def _layout_significantly_changed(self, new_positions: Dict) -> bool:
        """Check if the layout has significantly changed"""
        if not self.last_render:
            return True

        # Compare key dimensions
        if 'main' in new_positions:
            old_main_width = len(self.last_render.get('main_content', [''])[0]) if self.last_render.get('main_content') else 0
            new_main_width = new_positions['main']['width']

            # If width changed by more than 10 characters, consider it significant
            return abs(new_main_width - old_main_width) > 10

        return True

    def activate(self) -> None:
        """Activate the dashboard renderer"""
        self.active = True
        self.animation_state = AnimationState.RUNNING

    def deactivate(self) -> None:
        """Deactivate the dashboard renderer"""
        self.active = False
        self.animation_state = AnimationState.STOPPED
        self.animation_controller.stop_animation()

    def is_active(self) -> bool:
        """Check if the dashboard is currently active"""
        return self.active

    def get_animation_controller(self) -> AnimationController:
        """Get the animation controller for external use"""
        return self.animation_controller


# Convenience functions for dashboard creation
def create_dashboard(layout_engine: Optional[LayoutEngine] = None) -> DashboardRenderer:
    """Create a new dashboard renderer instance"""
    return DashboardRenderer(layout_engine)


def render_simple_banner(title: str, subtitle: str = "", width: int = 70) -> str:
    """Render a simple banner without full dashboard setup"""
    if width < 20:
        width = 20

    border = '═' * (width - 2)
    title_line = f" {title} ".center(width - 2)
    subtitle_line = f" {subtitle} ".center(width - 2) if subtitle else ""

    lines = [
        f'╔{border}╗',
        f'║{colored(title_line, "red", attrs=["bold"])}║',
    ]

    if subtitle_line:
        lines.append(f'║{colored(subtitle_line, "cyan")}║')

    lines.append(f'╚{border}╝')

    return '\n'.join(lines)