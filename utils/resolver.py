"""DNS and target resolution utilities"""

import socket
from .printer import Printer


class TargetResolver:
    """Resolves domain names to IP addresses"""

    @staticmethod
    def resolve_target(target):
        """
        Resolve target to IP addresses.

        Args:
            target: IP address or domain name

        Returns:
            List of IP addresses or None on failure
        """
        try:
            # Check if already an IP address
            socket.inet_aton(target)
            return [target]
        except socket.error:
            # Try DNS resolution
            try:
                addr_info = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
                ips = list({ai[4][0] for ai in addr_info})

                if not ips:
                    raise ValueError("No IP addresses found")

                Printer.status(f"Resolved {target} to {len(ips)} IPs:")
                for ip in ips:
                    Printer.status(f"  {ip}")
                return ips
            except Exception as e:
                Printer.error(f"Resolution failed: {str(e)}")
                return None
