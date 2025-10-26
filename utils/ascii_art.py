"""Enhanced ASCII art for CyberGuardian Ultimate"""

from termcolor import colored
import time
import sys
import random


class AsciiArt:
    """Beautiful ASCII art for the cybersecurity platform"""

    @staticmethod
    def main_banner():
        """Main banner with cyberpunk style"""
        banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██████╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗  ║
║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗ ║
║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ███╗██║   ██║███████║██████╔╝ ║
║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗ ║
║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║ ║
║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ║
║                                                                               ║
║                    ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗║
║                    ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝║
║                    ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗  ║
║                    ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝  ║
║                    ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗║
║                     ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝║
║                                                                               ║
║                     『 ULTIMATE CYBER WARFARE PLATFORM v2.0 』                 ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
        return colored(banner, 'cyan', attrs=['bold'])

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
            "Initializing quantum encryption modules",
            "Loading neural network exploit database",
            "Calibrating packet injection systems",
            "Establishing secure darknet connections",
            "Compiling zero-day vulnerability signatures",
            "Activating stealth reconnaissance protocols",
            "Synchronizing with global threat intelligence",
            "Deploying advanced penetration frameworks"
        ]

        colors = ['red', 'yellow', 'green', 'cyan', 'magenta']

        for i in range(8):
            sys.stdout.write('\033[2J\033[H')  # Clear screen
            frame = frames[i % len(frames)]
            color = colors[i % len(colors)]
            print(colored(frame, color, attrs=['bold']))

            # Progress bar
            progress = int((i + 1) / 8 * 50)
            bar = '█' * progress + '░' * (50 - progress)
            print(f"\n    [{colored(bar, color)}] {int((i + 1) / 8 * 100)}%")

            # Loading message
            if i < len(loading_messages):
                print(f"\n    {colored('>', 'green')} {loading_messages[i]}")

            sys.stdout.flush()
            time.sleep(0.3)

        # Final message
        sys.stdout.write('\033[2J\033[H')
        print(colored(frames[-1], 'green', attrs=['bold']))
        print(f"\n    [{colored('█' * 50, 'green')}] 100%")
        print(f"\n    {colored('✓', 'green', attrs=['bold'])} System ready. All modules loaded successfully.")
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
        """Generate banner for tool categories"""
        banners = {
            'recon': colored("""
    ╔══════════════════════════════════════╗
    ║   🔍 RECONNAISSANCE & ENUMERATION    ║
    ╚══════════════════════════════════════╝
            """, 'cyan'),
            'exploit': colored("""
    ╔══════════════════════════════════════╗
    ║   💣 EXPLOITATION & WEAPONIZATION    ║
    ╚══════════════════════════════════════╝
            """, 'red'),
            'web': colored("""
    ╔══════════════════════════════════════╗
    ║   🌐 WEB APPLICATION TESTING         ║
    ╚══════════════════════════════════════╝
            """, 'yellow'),
            'wireless': colored("""
    ╔══════════════════════════════════════╗
    ║   📡 WIRELESS SECURITY ASSESSMENT    ║
    ╚══════════════════════════════════════╝
            """, 'magenta'),
            'password': colored("""
    ╔══════════════════════════════════════╗
    ║   🔐 PASSWORD & HASH CRACKING        ║
    ╚══════════════════════════════════════╝
            """, 'blue'),
            'forensics': colored("""
    ╔══════════════════════════════════════╗
    ║   🔬 DIGITAL FORENSICS & OSINT       ║
    ╚══════════════════════════════════════╝
            """, 'green')
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
        print(f"\n{colored('ℹ', 'cyan', attrs=['bold'])} {colored(text, 'cyan')}\n")
