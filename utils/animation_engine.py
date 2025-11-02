"""Animation engine for subtle CLI animations and visual effects"""

import time
import threading
import sys
import os
from typing import Optional, Callable, Dict, Any, List
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum


class AnimationState(Enum):
    """Animation states for control flow"""
    STOPPED = "stopped"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"


@dataclass
class AnimationConfig:
    """Configuration settings for animations"""
    speed: float = 0.1  # Seconds between frames
    enabled: bool = True
    max_fps: int = 10   # Maximum frames per second to prevent performance issues
    interruptible: bool = True  # Can be interrupted by user input
    color_cycling: bool = True  # Enable color transitions where applicable


class AnimationController:
    """Manages subtle animations and visual effects for the CLI"""

    def __init__(self, config: Optional[AnimationConfig] = None):
        self.config = config or AnimationConfig()
        self.state = AnimationState.STOPPED
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._current_animation = None
        self._animation_thread = None

        # Animation symbols and frames
        self.spinner_frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.tech_symbols = ['⚡', '⟐', '◀', '▶', '●', '○', '◆', '◇']
        self.progress_chars = ['░', '▒', '▓', '█']
        self.connection_symbols = ['⚡', '🔗', '📡', '◈']

        # Color cycling colors (will be mapped to actual colors via color_compat)
        self.color_cycle = ['red', 'yellow', 'green', 'cyan', 'magenta']

    def _frame_delay(self) -> float:
        """Calculate delay between frames based on config"""
        return max(1.0 / self.config.max_fps, self.config.speed)

    def progress_bar(self,
                    current: int,
                    total: int,
                    width: int = 30,
                    show_percentage: bool = True,
                    show_eta: bool = False,
                    start_time: Optional[float] = None,
                    color: str = 'green') -> str:
        """Generate a smooth progress bar with customizable options"""
        if not self.config.enabled:
            return ""

        percentage = min(1.0, current / total)
        filled_chars = int(percentage * width)

        # Build the progress bar using progress characters for smooth appearance
        bar = ''
        for i in range(width):
            if i < filled_chars:
                bar += self.progress_chars[-1]  # Full block
            elif i == filled_chars and i < width:
                # Use a partial character for more precise representation
                partial = (percentage * width) % 1
                if partial < 0.25:
                    bar += self.progress_chars[0]  # Empty
                elif partial < 0.5:
                    bar += self.progress_chars[1]  # Light
                elif partial < 0.75:
                    bar += self.progress_chars[2]  # Medium
                else:
                    bar += self.progress_chars[3]  # Full
            else:
                bar += self.progress_chars[0]  # Empty block

        # Build the full progress string
        progress_str = f"[{bar}]"

        if show_percentage:
            progress_str += f" {percentage*100:.1f}%"

        if show_eta and start_time and current > 0:
            elapsed = time.time() - start_time
            if elapsed > 0:
                rate = current / elapsed
                remaining = (total - current) / rate if rate > 0 else 0
                eta_str = f" ETA: {remaining:.0f}s" if remaining > 0 else " Done!"
                progress_str += eta_str

        return progress_str

    def loading_spinner(self,
                       message: str = "Loading...",
                       symbol_set: str = "spinner",
                       color: str = 'cyan') -> None:
        """Display a subtle loading animation"""
        if not self.config.enabled:
            print(message)
            return

        def spinner_worker():
            """Background thread for spinner animation"""
            frame_index = 0
            symbols = self.spinner_frames if symbol_set == "spinner" else self.tech_symbols

            while not self._stop_event.is_set():
                if self.config.interruptible and self._pause_event.is_set():
                    time.sleep(0.1)
                    continue

                # Clear current line and show spinner
                sys.stdout.write(f'\r{symbols[frame_index]} {message}')
                sys.stdout.flush()

                frame_index = (frame_index + 1) % len(symbols)
                time.sleep(self._frame_delay())

        # Start spinner in background thread
        self._start_animation(spinner_worker)

    def status_pulse(self,
                    status_text: str,
                    symbol: str = '●',
                    color: str = 'green',
                    pulse_speed: float = 1.0) -> None:
        """Gentle pulsing effect for status indicators"""
        if not self.config.enabled:
            print(f"{symbol} {status_text}")
            return

        def pulse_worker():
            """Background thread for pulsing effect"""
            cycle_count = 0
            symbols = ['○', '●', '◉']  # Empty, filled, bright

            while not self._stop_event.is_set():
                if self.config.interruptible and self._pause_event.is_set():
                    time.sleep(0.1)
                    continue

                # Calculate which symbol to show based on cycle
                symbol_index = (cycle_count // int(pulse_speed * 10)) % len(symbols)
                current_symbol = symbols[symbol_index]

                sys.stdout.write(f'\r{current_symbol} {status_text}')
                sys.stdout.flush()

                cycle_count += 1
                time.sleep(self._frame_delay())

        self._start_animation(pulse_worker)

    def data_flow_animation(self,
                          direction: str = 'right',
                          width: int = 20,
                          symbol: str = '⟐') -> None:
        """Subtle data stream visualization"""
        if not self.config.enabled:
            return

        def flow_worker():
            """Background thread for data flow animation"""
            position = 0
            flow_chars = ['.', '..', '...', '....']

            while not self._stop_event.is_set():
                if self.config.interruptible and self._pause_event.is_set():
                    time.sleep(0.1)
                    continue

                # Create flow pattern
                flow_line = ' ' * width
                for i in range(0, width, 4):
                    flow_pos = (position + i) % width
                    if flow_pos < len(flow_line):
                        flow_line = flow_line[:flow_pos] + symbol + flow_line[flow_pos + 1:]

                sys.stdout.write(f'\r{flow_line}')
                sys.stdout.flush()

                position += 1 if direction == 'right' else -1
                time.sleep(self._frame_delay())

        self._start_animation(flow_worker)

    def typing_effect(self,
                    text: str,
                    speed: float = 0.05,
                    color: str = 'white') -> None:
        """Simulate typing effect for text"""
        if not self.config.enabled:
            print(text)
            return

        for char in text:
            if self._stop_event.is_set():
                break

            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(speed)

        print()  # New line at the end

    def color_animation(self,
                       text: str,
                       colors: List[str] = None,
                       cycle_speed: float = 0.5) -> str:
        """Apply subtle color cycling to text (returns formatted text for immediate display)"""
        if not self.config.enabled or not self.config.color_cycling:
            return text

        colors = colors or self.color_cycle

        # For now, return text with first color - actual cycling would need terminal control
        # In a real implementation, this could use ANSI color codes with timing
        from .color_compat import colored
        return colored(text, colors[0])

    def connection_indicator(self,
                           status: str = 'connecting',
                           host: str = '') -> None:
        """Network connection health indicator with tech symbols"""
        if not self.config.enabled:
            print(f"Connection {status}: {host}")
            return

        def connection_worker():
            """Background thread for connection status animation"""
            symbol_index = 0
            status_messages = {
                'connecting': 'Establishing connection',
                'authenticating': 'Authenticating',
                'connected': 'Connection established',
                'error': 'Connection failed'
            }

            message = status_messages.get(status, status)

            while not self._stop_event.is_set():
                if self.config.interruptible and self._pause_event.is_set():
                    time.sleep(0.1)
                    continue

                symbol = self.connection_symbols[symbol_index % len(self.connection_symbols)]
                display_text = f"{symbol} {message}"
                if host:
                    display_text += f" - {host}"

                sys.stdout.write(f'\r{display_text}')
                sys.stdout.flush()

                symbol_index += 1
                time.sleep(self._frame_delay() * 2)  # Slower for connection indicator

        self._start_animation(connection_worker)

    def _start_animation(self, worker_func: Callable) -> None:
        """Start an animation in a background thread"""
        if self._animation_thread and self._animation_thread.is_alive():
            self.stop_animation()

        self._stop_event.clear()
        self._pause_event.clear()
        self.state = AnimationState.RUNNING

        self._animation_thread = threading.Thread(target=worker_func, daemon=True)
        self._animation_thread.start()

    def stop_animation(self) -> None:
        """Stop the current animation"""
        if self.state == AnimationState.RUNNING:
            self._stop_event.set()
            if self._animation_thread:
                self._animation_thread.join(timeout=1.0)
            self.state = AnimationState.STOPPED
            sys.stdout.write('\r')  # Clear current line
            sys.stdout.flush()

    def pause_animation(self) -> None:
        """Pause the current animation"""
        if self.state == AnimationState.RUNNING:
            self._pause_event.set()
            self.state = AnimationState.PAUSED

    def resume_animation(self) -> None:
        """Resume a paused animation"""
        if self.state == AnimationState.PAUSED:
            self._pause_event.clear()
            self.state = AnimationState.RUNNING

    @contextmanager
    def animation_context(self, animation_type: str = 'spinner', **kwargs):
        """Context manager for automatic animation cleanup"""
        try:
            if animation_type == 'spinner':
                self.loading_spinner(**kwargs)
            elif animation_type == 'status':
                self.status_pulse(**kwargs)
            elif animation_type == 'data_flow':
                self.data_flow_animation(**kwargs)
            elif animation_type == 'connection':
                self.connection_indicator(**kwargs)

            yield self
        finally:
            self.stop_animation()

    def create_progress_tracker(self,
                              total: int,
                              description: str = "Progress") -> 'ProgressTracker':
        """Create a progress tracker with built-in animation support"""
        return ProgressTracker(self, total, description)


class ProgressTracker:
    """Enhanced progress tracking with animation support"""

    def __init__(self,
                 animation_controller: AnimationController,
                 total: int,
                 description: str = "Progress"):
        self.controller = animation_controller
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = None
        self.last_update = 0

    def update(self, increment: int = 1, force_update: bool = False) -> None:
        """Update progress with optional forced display"""
        self.current += increment
        if self.start_time is None:
            self.start_time = time.time()

        # Throttle updates to prevent display spam
        current_time = time.time()
        if force_update or current_time - self.last_update > 0.1:  # Update every 100ms max
            self._display_progress()
            self.last_update = current_time

    def set_current(self, value: int) -> None:
        """Set current progress value directly"""
        self.current = max(0, min(value, self.total))
        if self.start_time is None:
            self.start_time = time.time()
        self._display_progress()

    def _display_progress(self) -> None:
        """Display current progress"""
        progress_bar = self.controller.progress_bar(
            self.current,
            self.total,
            show_percentage=True,
            show_eta=True,
            start_time=self.start_time
        )

        sys.stdout.write(f'\r{self.description}: {progress_bar}')
        sys.stdout.flush()

    def finish(self, final_message: str = "Complete!") -> None:
        """Mark progress as complete"""
        self.current = self.total
        self._display_progress()
        sys.stdout.write(f' - {final_message}\n')
        sys.stdout.flush()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.current < self.total:
            self.finish("Interrupted")


# Global animation controller instance
_global_controller = None


def get_animation_controller() -> AnimationController:
    """Get or create the global animation controller"""
    global _global_controller
    if _global_controller is None:
        _global_controller = AnimationController()
    return _global_controller


def create_progress_tracker(total: int, description: str = "Progress") -> ProgressTracker:
    """Create a progress tracker using the global animation controller"""
    controller = get_animation_controller()
    return controller.create_progress_tracker(total, description)


@contextmanager
def loading_animation(message: str = "Loading...", **kwargs):
    """Convenient context manager for loading animations"""
    controller = get_animation_controller()
    with controller.animation_context('spinner', message=message, **kwargs):
        yield controller


# Disable animations for performance or user preference
def disable_animations():
    """Disable all animations globally"""
    controller = get_animation_controller()
    controller.config.enabled = False


def enable_animations():
    """Enable all animations globally"""
    controller = get_animation_controller()
    controller.config.enabled = True