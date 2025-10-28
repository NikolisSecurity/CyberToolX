"""Enhanced ASCII art for NPS Tool"""

from .color_compat import colored
import time
import sys
import random
import requests
import getpass


class AsciiArt:
    """Beautiful ASCII art for the cybersecurity platform"""

    @staticmethod
    def get_public_ip():
        """Fetch public IP address from ipify.org API"""
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=3)
            return response.json()['ip']
        except Exception:
            return "Unavailable"

    @staticmethod
    def main_banner(target=None):
        """Main banner with compact box-drawing style"""
        # Get target display
        target_display = target if target else "Not Set"

        # Fetch public IP
        public_ip = AsciiArt.get_public_ip()

        # Build account info box
        account_box = f"""╒═════════════════════╕
│ Account Information │
│ Target: {target_display:<11} │
│ IP: {public_ip:<15} │
╘═════════════════════╛"""

        # Horizontal separator
        separator = "\n══╦═════════════════════════════════════╦══"

        # Tool title box
        title_box = """╔════════════════════════════════════════╗
│  NPS Tool                              │
│  Advanced Web Security Testing         │
╚════════════════════════════════════════╝"""

        # Combine all parts with neon red theme
        banner = colored(account_box, 'red') + colored(separator, 'red') + "\n" + colored(title_box, 'red')

        return banner

    @staticmethod
    def loading_screen():
        """Animated loading screen"""
        frames = [
            """
    ██╗      ██████╗  █████╗ ██████╗ ██╗███╗   ██╗ ██████╗
    ██║     ██╔═══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔════╝
    ██║     ██║   ██║███████║██║  ██║██║██╔██╗ ██║██║  ███╗
    ██║     ██║   ██║██╔══██║██║  ██║██║██║╚██╗██║██║   ██║
    ███████╗╚██████╔╝██║  ██║██████╔╝██║██║ ╚████║╚██████╔╝
    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝
            """,
            """
    ██╗      ██████╗  █████╗ ██████╗ ██╗███╗   ██╗ ██████╗
    ██║     ██╔═══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔════╝•
    ██║     ██║   ██║███████║██║  ██║██║██╔██╗ ██║██║  ███╗
    ██║     ██║   ██║██╔══██║██║  ██║██║██║╚██╗██║██║   ██║
    ███████╗╚██████╔╝██║  ██║██████╔╝██║██║ ╚████║╚██████╔╝
    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝
            """,
            """
    ██╗      ██████╗  █████╗ ██████╗ ██╗███╗   ██╗ ██████╗
    ██║     ██╔═══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔════╝••
    ██║     ██║   ██║███████║██║  ██║██║██╔██╗ ██║██║  ███╗
    ██║     ██║   ██║██╔══██║██║  ██║██║██║╚██╗██║██║   ██║
    ███████╗╚██████╔╝██║  ██║██████╔╝██║██║ ╚████║╚██████╔╝
    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝
            """,
            """
    ██╗      ██████╗  █████╗ ██████╗ ██╗███╗   ██╗ ██████╗
    ██║     ██╔═══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔════╝•••
    ██║     ██║   ██║███████║██║  ██║██║██╔██╗ ██║██║  ███╗
    ██║     ██║   ██║██╔══██║██║  ██║██║██║╚██╗██║██║   ██║
    ███████╗╚██████╔╝██║  ██║██████╔╝██║██║ ╚████║╚██████╔╝
    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝
            """
        ]

        loading_messages = [
            "Initializing web vulnerability scanners",
            "Loading SSL/TLS analysis modules",
            "Preparing SQL injection testers",
            "Loading XSS detection engine",
            "Initializing header security scanner",
            "Loading WAF detection system"
        ]

        colors = ['red', 'yellow', 'green']  # Neon red-spectrum cycling

        for i in range(6):
            sys.stdout.write('\033[2J\033[H')  # Clear screen
            frame = frames[i % len(frames)]
            color = colors[i % len(colors)]
            print(colored(frame, color, attrs=['bold']))

            # Progress bar
            progress = int((i + 1) / 6 * 50)
            bar = '█' * progress + '░' * (50 - progress)
            print(f"\n    [{colored(bar, color)}] {int((i + 1) / 6 * 100)}%")

            # Loading message
            if i < len(loading_messages):
                print(f"\n    {colored('>', 'green')} {loading_messages[i]}")

            sys.stdout.flush()
            time.sleep(0.3)

        # Final message
        sys.stdout.write('\033[2J\033[H')
        print(colored(frames[-1], 'green', attrs=['bold']))
        print(f"\n    [{colored('█' * 50, 'green')}] 100%")
        print(f"\n    {colored('✓', 'green', attrs=['bold'])} System ready - Web security modules loaded.")
        time.sleep(1)

    @staticmethod
    def skull():
        """Skull ASCII art for aggressive mode"""
        skull = """
                       ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄
                      ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
                       ▀▀▀▀█░█▀▀▀▀  ▀▀▀▀█░█▀▀▀▀
                           ▐░▌          ▐░▌
                            ▀            ▀
        """
        return colored(skull, 'red', attrs=['bold'])

    @staticmethod
    def shield():
        """Shield ASCII art for defensive mode"""
        shield = """
                          ╔═══════════════╗
                          ║   ▄▀▀▀▀▀▀▀▄   ║
                          ║  █  CYBER  █  ║
                          ║  █ SHIELD █  ║
                          ║   ▀▄▄▄▄▄▄▄▀   ║
                          ╚═══════════════╝
        """
        return colored(shield, 'blue', attrs=['bold'])

    @staticmethod
    def matrix_rain(duration=2):
        """Matrix-style falling characters effect"""
        chars = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜｦﾝ0123456789"

        # Simple matrix effect for a few iterations
        for _ in range(int(duration * 10)):
            line = ''.join(random.choice(chars) for _ in range(80))
            print(colored(line, 'green'))
            time.sleep(0.1)

    @staticmethod
    def hacker_typer(text, speed=0.03):
        """Simulate hacker typing effect"""
        for char in text:
            sys.stdout.write(colored(char, 'green'))
            sys.stdout.flush()
            time.sleep(speed)
        print()

    @staticmethod
    def tool_category_banner(category):
        """Generate banner for tool categories with neon red theme"""
        banners = {
            'recon': colored("""
    ╔══════════════════════════════════════╗
    ║   🔍 RECONNAISSANCE & ENUMERATION    ║
    ╚══════════════════════════════════════╝
            """, 'magenta'),  # Lighter pink-red
            'exploit': colored("""
    ╔══════════════════════════════════════╗
    ║   💣 EXPLOITATION & WEAPONIZATION    ║
    ╚══════════════════════════════════════╝
            """, 'red'),  # Neon red
            'web': colored("""
    ╔══════════════════════════════════════╗
    ║   🌐 WEB APPLICATION TESTING         ║
    ╚══════════════════════════════════════╝
            """, 'red'),  # Neon red
            'wireless': colored("""
    ╔══════════════════════════════════════╗
    ║   📡 WIRELESS SECURITY ASSESSMENT    ║
    ╚══════════════════════════════════════╝
            """, 'magenta'),  # Lighter pink-red
            'password': colored("""
    ╔══════════════════════════════════════╗
    ║   🔐 PASSWORD & HASH CRACKING        ║
    ╚══════════════════════════════════════╝
            """, 'red'),  # Neon red
            'forensics': colored("""
    ╔══════════════════════════════════════╗
    ║   🔬 DIGITAL FORENSICS & OSINT       ║
    ╚══════════════════════════════════════╝
            """, 'magenta')  # Lighter pink-red
        }
        return banners.get(category, "")

    @staticmethod
    def success_message(text):
        """Beautiful success message"""
        print(f"\n{colored('✓', 'green', attrs=['bold'])} {colored(text, 'green')}\n")

    @staticmethod
    def error_message(text):
        """Beautiful error message"""
        print(f"\n{colored('✗', 'red', attrs=['bold'])} {colored(text, 'red')}\n")

    @staticmethod
    def warning_message(text):
        """Beautiful warning message"""
        print(f"\n{colored('⚠', 'yellow', attrs=['bold'])} {colored(text, 'yellow')}\n")

    @staticmethod
    def info_message(text):
        """Beautiful info message"""
        print(f"\n{colored('ℹ', 'blue', attrs=['bold'])} {colored(text, 'blue')}\n")  # Lighter pink-red
