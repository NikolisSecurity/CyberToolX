"""Enhanced progress indicators and status displays for the CLI"""

import time
import threading
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

from .color_compat import colored
from .animation_engine import AnimationController, ProgressTracker


class ScanPhase(Enum):
    """Different phases of a security scan"""
    INITIALIZING = "initializing"
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    COMPLETE = "complete"


class ToolExecutionStatus(Enum):
    """Status of tool execution"""
    IDLE = "idle"
    PREPARING = "preparing"
    RUNNING = "running"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ConnectionStatus(Enum):
    """Network connection status"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTHENTICATED = "authenticated"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class ScanStage:
    """Individual stage within a scan"""
    name: str
    phase: ScanPhase
    progress: float = 0.0  # 0.0 to 1.0
    status: str = "pending"
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    details: str = ""


@dataclass
class ToolMetrics:
    """Metrics for tool execution"""
    tool_name: str
    target: str
    status: ToolExecutionStatus
    start_time: float
    progress: float = 0.0
    items_processed: int = 0
    total_items: int = 0
    current_operation: str = ""
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class ProgressIndicator:
    """Enhanced progress indicators and status displays"""

    def __init__(self, animation_controller: Optional[AnimationController] = None):
        self.animation_controller = animation_controller or AnimationController()

        # Scan progress tracking
        self.scan_stages: List[ScanStage] = []
        self.current_scan_phase = ScanPhase.INITIALIZING
        self.scan_start_time: Optional[float] = None
        self.scan_progress: float = 0.0

        # Tool execution tracking
        self.active_tools: Dict[str, ToolMetrics] = {}
        self.completed_tools: List[ToolMetrics] = []

        # Connection status tracking
        self.connection_status = ConnectionStatus.DISCONNECTED
        self.connection_host: str = ""
        self.connection_start_time: Optional[float] = None

        # System metrics
        self.system_metrics = {
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'network_requests': 0,
            'errors_count': 0
        }

        # Threading for background updates
        self._update_thread = None
        self._stop_update_thread = threading.Event()

    def scan_progress(self, phases: List[Dict[str, Any]], current_phase_index: int = 0) -> str:
        """Multi-stage scan progress with phase indicators"""
        if not phases:
            return ""

        total_phases = len(phases)
        completed_phases = current_phase_index

        # Calculate overall progress
        overall_progress = completed_phases / total_phases

        # Build phase indicators
        phase_indicators = []
        for i, phase in enumerate(phases):
            phase_name = phase.get('name', f'Phase {i+1}')
            phase_symbol = self._get_phase_symbol(i, current_phase_index)
            phase_color = self._get_phase_color(i, current_phase_index, phase.get('status', 'pending'))

            if i <= current_phase_index:
                indicator = colored(f"{phase_symbol} {phase_name}", phase_color)
            else:
                indicator = colored(f"○ {phase_name}", 'white', attrs=['dark'])

            phase_indicators.append(indicator)

        # Create progress bar
        bar_width = 30
        filled_width = int(overall_progress * bar_width)
        progress_bar = '█' * filled_width + '░' * (bar_width - filled_width)

        # Format output
        lines = [
            colored("SCAN PROGRESS", 'cyan', attrs=['bold']),
            f"[{colored(progress_bar, 'green')}] {overall_progress*100:.1f}%",
            "",
            " ".join(phase_indicators)
        ]

        return "\n".join(lines)

    def tool_execution_status(self, tool_name: str, metrics: ToolMetrics) -> str:
        """Real-time tool status with animated symbols"""
        status_symbol = self._get_tool_status_symbol(metrics.status)
        status_color = self._get_tool_status_color(metrics.status)

        # Build status line
        status_line = f"{colored(status_symbol, status_color)} {colored(tool_name, 'white', attrs=['bold'])}"

        # Add progress if running
        if metrics.status in [ToolExecutionStatus.RUNNING, ToolExecutionStatus.ANALYZING]:
            progress_bar = self.animation_controller.progress_bar(
                metrics.items_processed,
                metrics.total_items,
                width=20,
                show_percentage=True
            )
            status_line += f" {progress_bar}"

        # Add current operation
        if metrics.current_operation:
            status_line += f"\n  {colored('→', 'cyan')} {metrics.current_operation}"

        # Add processing details
        if metrics.total_items > 0:
            details = f"Items: {metrics.items_processed}/{metrics.total_items}"
            status_line += f"\n  {colored('📊', 'yellow')} {details}"

        # Add errors/warnings if any
        if metrics.errors:
            error_count = len(metrics.errors)
            status_line += f"\n  {colored('✗', 'red')} {error_count} error(s)"

        if metrics.warnings:
            warning_count = len(metrics.warnings)
            status_line += f"\n  {colored('⚠', 'yellow')} {warning_count} warning(s)"

        return status_line

    def connection_status(self, host: str = "", port: int = 0) -> str:
        """Network connection health indicator"""
        if host:
            self.connection_host = host
            if port:
                self.connection_host += f":{port}"

        status_symbol = self._get_connection_status_symbol()
        status_color = self._get_connection_status_color()
        status_text = self._get_connection_status_text()

        # Build connection status display
        connection_line = f"{colored(status_symbol, status_color)} {colored(status_text, status_color)}"

        if self.connection_host:
            connection_line += f" - {colored(self.connection_host, 'cyan')}"

        # Add connection duration if connected
        if (self.connection_status in [ConnectionStatus.CONNECTED, ConnectionStatus.AUTHENTICATED]
            and self.connection_start_time):
            duration = time.time() - self.connection_start_time
            connection_line += f" ({duration:.1f}s)"

        return connection_line

    def system_metrics(self, metrics: Dict[str, float] = None) -> str:
        """CPU/memory usage in cyber-themed format"""
        if metrics:
            self.system_metrics.update(metrics)

        # Create cyber-themed metrics display
        lines = [colored("SYSTEM METRICS", 'cyan', attrs=['bold'])]

        # CPU usage with cyber symbols
        cpu_usage = self.system_metrics.get('cpu_usage', 0)
        cpu_symbol = self._get_performance_symbol(cpu_usage)
        cpu_color = self._get_performance_color(cpu_usage)
        lines.append(f"{cpu_symbol} CPU: {colored(f'{cpu_usage:.1f}%', cpu_color)}")

        # Memory usage
        memory_usage = self.system_metrics.get('memory_usage', 0)
        memory_symbol = self._get_performance_symbol(memory_usage)
        memory_color = self._get_performance_color(memory_usage)
        lines.append(f"{memory_symbol} MEM: {colored(f'{memory_usage:.1f}%', memory_color)}")

        # Network requests
        network_requests = self.system_metrics.get('network_requests', 0)
        lines.append(f"📡 NET: {colored(f'{network_requests:,}', 'green')} requests")

        # Error count
        errors_count = self.system_metrics.get('errors_count', 0)
        if errors_count > 0:
            lines.append(f"✗ ERR: {colored(f'{errors_count}', 'red')}")

        return "\n".join(lines)

    def color_coded_progress(self, progress: float, width: int = 30, show_text: bool = True) -> str:
        """Progress bar with color coding based on progress percentage"""
        # Determine color based on progress
        if progress < 0.3:
            color = 'red'      # Slow progress
        elif progress < 0.7:
            color = 'yellow'   # Moderate progress
        else:
            color = 'green'    # Good progress

        # Create progress bar
        filled_chars = int(progress * width)
        bar = '█' * filled_chars + '░' * (width - filled_chars)

        result = f"[{colored(bar, color)}]"

        if show_text:
            result += f" {progress*100:.1f}%"

        return result

    def animated_milestones(self, milestones: List[Dict[str, Any]], current_index: int = 0) -> str:
        """Animated milestones for key completion points"""
        lines = [colored("SCAN MILESTONES", 'cyan', attrs=['bold'])]

        for i, milestone in enumerate(milestones):
            name = milestone.get('name', f'Milestone {i+1}')
            completed = i < current_index
            current = i == current_index

            if completed:
                symbol = colored('✓', 'green')
                text = colored(name, 'green')
            elif current:
                symbol = colored('⟳', 'yellow')
                text = colored(name, 'yellow', attrs=['bold'])
            else:
                symbol = colored('○', 'white', attrs=['dark'])
                text = colored(name, 'white', attrs=['dark'])

            lines.append(f"{symbol} {text}")

        return "\n".join(lines)

    def time_estimates(self, start_time: float, current_progress: float, total_items: Optional[int] = None) -> str:
        """ETA calculations with multiple time estimates"""
        elapsed = time.time() - start_time

        if current_progress <= 0:
            return "Calculating ETA..."

        # Estimate total time
        estimated_total = elapsed / current_progress
        remaining = estimated_total - elapsed

        # Format times
        elapsed_str = self._format_duration(elapsed)
        remaining_str = self._format_duration(remaining)
        total_str = self._format_duration(estimated_total)

        lines = [
            colored("TIME ESTIMATES", 'cyan', attrs=['bold']),
            f"⏱ Elapsed: {colored(elapsed_str, 'green')}",
            f"⏳ Remaining: {colored(remaining_str, 'yellow')}",
            f"🕐 Total: {colored(total_str, 'white')}"
        ]

        # Add rate information if items are being processed
        if total_items and current_progress > 0:
            items_per_second = (total_items * current_progress) / elapsed
            lines.append(f"⚡ Rate: {colored(f'{items_per_second:.1f} items/sec', 'cyan')}")

        return "\n".join(lines)

    def _get_phase_symbol(self, phase_index: int, current_phase_index: int) -> str:
        """Get appropriate symbol for scan phase"""
        if phase_index < current_phase_index:
            return '✓'
        elif phase_index == current_phase_index:
            return '⟳'
        else:
            return '○'

    def _get_phase_color(self, phase_index: int, current_phase_index: int, status: str) -> str:
        """Get appropriate color for scan phase"""
        if phase_index < current_phase_index:
            return 'green'
        elif phase_index == current_phase_index:
            if status == 'complete':
                return 'green'
            elif status == 'error':
                return 'red'
            else:
                return 'yellow'
        else:
            return 'white'

    def _get_tool_status_symbol(self, status: ToolExecutionStatus) -> str:
        """Get symbol for tool execution status"""
        symbols = {
            ToolExecutionStatus.IDLE: '○',
            ToolExecutionStatus.PREPARING: '⚡',
            ToolExecutionStatus.RUNNING: '⟳',
            ToolExecutionStatus.ANALYZING: '🔬',
            ToolExecutionStatus.COMPLETE: '✓',
            ToolExecutionStatus.FAILED: '✗',
            ToolExecutionStatus.CANCELLED: '◼'
        }
        return symbols.get(status, '○')

    def _get_tool_status_color(self, status: ToolExecutionStatus) -> str:
        """Get color for tool execution status"""
        colors = {
            ToolExecutionStatus.IDLE: 'white',
            ToolExecutionStatus.PREPARING: 'yellow',
            ToolExecutionStatus.RUNNING: 'cyan',
            ToolExecutionStatus.ANALYZING: 'magenta',
            ToolExecutionStatus.COMPLETE: 'green',
            ToolExecutionStatus.FAILED: 'red',
            ToolExecutionStatus.CANCELLED: 'white'
        }
        return colors.get(status, 'white')

    def _get_connection_status_symbol(self) -> str:
        """Get symbol for connection status"""
        symbols = {
            ConnectionStatus.DISCONNECTED: '○',
            ConnectionStatus.CONNECTING: '⟳',
            ConnectionStatus.CONNECTED: '●',
            ConnectionStatus.AUTHENTICATED: '🔒',
            ConnectionStatus.ERROR: '✗',
            ConnectionStatus.TIMEOUT: '⏰'
        }
        return symbols.get(self.connection_status, '○')

    def _get_connection_status_color(self) -> str:
        """Get color for connection status"""
        colors = {
            ConnectionStatus.DISCONNECTED: 'white',
            ConnectionStatus.CONNECTING: 'yellow',
            ConnectionStatus.CONNECTED: 'green',
            ConnectionStatus.AUTHENTICATED: 'cyan',
            ConnectionStatus.ERROR: 'red',
            ConnectionStatus.TIMEOUT: 'red'
        }
        return colors.get(self.connection_status, 'white')

    def _get_connection_status_text(self) -> str:
        """Get text for connection status"""
        texts = {
            ConnectionStatus.DISCONNECTED: 'Disconnected',
            ConnectionStatus.CONNECTING: 'Connecting',
            ConnectionStatus.CONNECTED: 'Connected',
            ConnectionStatus.AUTHENTICATED: 'Authenticated',
            ConnectionStatus.ERROR: 'Connection Error',
            ConnectionStatus.TIMEOUT: 'Connection Timeout'
        }
        return texts.get(self.connection_status, 'Unknown')

    def _get_performance_symbol(self, usage: float) -> str:
        """Get cyber-themed symbol for performance metrics"""
        if usage < 30:
            return '●'  # Low usage
        elif usage < 60:
            return '◐'  # Medium usage
        elif usage < 80:
            return '◑'  # High usage
        else:
            return '◉'  # Critical usage

    def _get_performance_color(self, usage: float) -> str:
        """Get color for performance metrics"""
        if usage < 30:
            return 'green'
        elif usage < 60:
            return 'yellow'
        elif usage < 80:
            return 'red'
        else:
            return 'red'  # Critical usage

    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"

    def start_background_updates(self, update_interval: float = 1.0) -> None:
        """Start background thread for updating progress indicators"""
        if self._update_thread and self._update_thread.is_alive():
            return

        self._stop_update_thread.clear()

        def update_worker():
            while not self._stop_update_thread.is_set():
                # Update dynamic content here
                time.sleep(update_interval)

        self._update_thread = threading.Thread(target=update_worker, daemon=True)
        self._update_thread.start()

    def stop_background_updates(self) -> None:
        """Stop background update thread"""
        self._stop_update_thread.set()
        if self._update_thread:
            self._update_thread.join(timeout=2.0)


# Convenience functions for creating progress indicators
def create_scan_progress_indicator() -> ProgressIndicator:
    """Create a progress indicator for scan tracking"""
    return ProgressIndicator()


def create_tool_status_tracker(tool_name: str, target: str) -> ToolMetrics:
    """Create a new tool metrics tracker"""
    return ToolMetrics(
        tool_name=tool_name,
        target=target,
        status=ToolExecutionStatus.IDLE,
        start_time=time.time()
    )


def create_connection_tracker() -> ProgressIndicator:
    """Create a progress indicator for connection tracking"""
    return ProgressIndicator()