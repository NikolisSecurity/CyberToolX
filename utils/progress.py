"""Scan progress tracking"""

import threading
import time


class ScanProgress:
    """Thread-safe progress tracker for scans"""

    def __init__(self):
        self.lock = threading.Lock()
        self.port_total = 0
        self.port_current = 0
        self.dir_total = 0
        self.dir_current = 0
        self.scan_start = time.time()

    def update_ports(self, current, total):
        """Update port scan progress"""
        with self.lock:
            self.port_current = current
            self.port_total = total

    def update_dirs(self, current, total):
        """Update directory enumeration progress"""
        with self.lock:
            self.dir_current = current
            self.dir_total = total

    def get_progress(self):
        """Get current progress statistics"""
        with self.lock:
            elapsed = time.time() - self.scan_start
            port_pct = (self.port_current/self.port_total)*100 if self.port_total else 0
            dir_pct = (self.dir_current/self.dir_total)*100 if self.dir_total else 0
            return {
                'ports': f"{port_pct:.1f}%",
                'directories': f"{dir_pct:.1f}%",
                'elapsed': f"{elapsed:.1f}s"
            }
