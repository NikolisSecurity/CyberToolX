"""Port range and specification parser"""


# Top 100 most common ports for quick scans
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 20, 69, 161, 162, 389, 636,
    1433, 1521, 3268, 5432, 5800, 5985, 5986, 6379, 8000, 8001, 8008, 8081,
    8082, 8090, 9000, 9090, 9200, 9443, 10000, 27017, 27018, 50000, 123, 137,
    138, 199, 427, 444, 465, 513, 514, 515, 548, 554, 587, 631, 646, 873,
    990, 1025, 1026, 1027, 1028, 1029, 1080, 1110, 1194, 1337, 1812, 1813,
    1900, 2049, 2121, 2375, 2376, 2483, 2484, 3001, 3128, 4444, 4445, 4567,
    5000, 5001, 5060, 5222, 6000, 6001, 6666, 7001, 7777, 8009, 9001, 9091
]


class PortParser:
    """Parse port specifications into nmap-compatible port ranges"""

    @staticmethod
    def parse_ports(port_spec):
        """
        Parse port specification into nmap port string.

        Supported formats:
        - Single port: "80"
        - Port list: "80,443,8080"
        - Port range: "1-1000"
        - Mixed: "21,22,80-443,3306,8000-9000"
        - Common: "common" (top 100 ports)

        Args:
            port_spec: Port specification string

        Returns:
            tuple: (port_string, port_count) for nmap

        Raises:
            ValueError: If port specification is invalid
        """
        if not port_spec:
            raise ValueError("Port specification cannot be empty")

        # Handle 'common' keyword
        if port_spec.lower() == 'common':
            ports_str = ','.join(map(str, sorted(COMMON_PORTS)))
            return (ports_str, len(COMMON_PORTS))

        # Parse port specification
        ports_set = set()

        # Split by comma
        parts = port_spec.split(',')

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Check for range (e.g., "80-443")
            if '-' in part:
                try:
                    start, end = part.split('-', 1)
                    start = int(start.strip())
                    end = int(end.strip())

                    # Validate port range
                    if start < 1 or end > 65535:
                        raise ValueError(f"Port must be between 1 and 65535: {part}")
                    if start > end:
                        raise ValueError(f"Invalid port range (start > end): {part}")
                    if end - start > 30000:
                        from utils.printer import Printer
                        Printer.warning(f"Scanning {end - start + 1} ports may take a long time")

                    # Add all ports in range
                    for port in range(start, end + 1):
                        ports_set.add(port)

                except ValueError as e:
                    if "invalid literal" in str(e):
                        raise ValueError(f"Invalid port number in range: {part}")
                    raise

            # Single port
            else:
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Port must be between 1 and 65535: {port}")
                    ports_set.add(port)
                except ValueError:
                    raise ValueError(f"Invalid port number: {part}")

        if not ports_set:
            raise ValueError("No valid ports specified")

        # Warn if scanning too many ports
        if len(ports_set) > 10000:
            from utils.printer import Printer
            response = input(f"Warning: Scanning {len(ports_set)} ports may take hours. Continue? (y/n): ")
            if response.lower() != 'y':
                raise ValueError("Scan cancelled by user")

        # Convert to nmap-compatible string (sort and create ranges)
        port_list = sorted(ports_set)
        port_string = PortParser._optimize_port_string(port_list)

        return (port_string, len(ports_set))

    @staticmethod
    def _optimize_port_string(ports):
        """
        Optimize port list into ranges for nmap.

        Example: [80, 81, 82, 443, 8080] -> "80-82,443,8080"
        """
        if not ports:
            return ""

        result = []
        start = ports[0]
        end = ports[0]

        for i in range(1, len(ports)):
            if ports[i] == end + 1:
                # Continue range
                end = ports[i]
            else:
                # End of range
                if start == end:
                    result.append(str(start))
                else:
                    result.append(f"{start}-{end}")
                start = ports[i]
                end = ports[i]

        # Add last range
        if start == end:
            result.append(str(start))
        else:
            result.append(f"{start}-{end}")

        return ','.join(result)
