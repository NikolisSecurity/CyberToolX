"""Enhanced ASCII art for NPS Tool"""

from .color_compat import colored
import time
import sys
import random
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
import getpass


class AsciiArt:
    """Beautiful ASCII art for the cybersecurity platform"""

    @staticmethod
    def get_public_ip():
        """Fetch public IP address from ipify.org API"""
        if not HAS_REQUESTS:
            return "Unavailable (no requests module)"
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=3)
            return response.json()['ip']
        except Exception:
            return "Unavailable"

    @staticmethod
    def main_banner(target=None, style='circuit_board'):
        """Enhanced main banner with cyber-themed styles"""
        # Get target display
        target_display = target if target else "Not Set"

        # Fetch public IP
        public_ip = AsciiArt.get_public_ip()

        # Get cyber symbols based on style
        cyber_symbols = AsciiArt.get_cyber_symbols(style)

        # Build account info box with cyber theme
        account_box = f"""{cyber_symbols['top_left']}{cyber_symbols['horizontal'] * 21}{cyber_symbols['top_right']}
{cyber_symbols['vertical']} Account Information {cyber_symbols['vertical']}
{cyber_symbols['vertical']} Target: {target_display:<11} {cyber_symbols['vertical']}
{cyber_symbols['vertical']} IP: {public_ip:<15} {cyber_symbols['vertical']}
{cyber_symbols['bottom_left']}{cyber_symbols['horizontal'] * 21}{cyber_symbols['bottom_right']}"""

        # Horizontal separator with tech symbols
        separator = f"\n{cyber_symbols['cross']}{cyber_symbols['horizontal'] * 45}{cyber_symbols['cross']}"

        # Enhanced tool title with cyber art
        title_box = AsciiArt._get_styled_banner(style, target_display)

        # Combine all parts with theme colors
        banner = colored(account_box, 'tech_cyan') + colored(separator, 'cyber_purple') + "\n" + title_box

        return banner

    @staticmethod
    def get_cyber_symbols(style='circuit_board'):
        """Get cyber symbol collections for different styles"""
        try:
            from config import ASCII_ART_STYLES
            style_config = ASCII_ART_STYLES.get(style, ASCII_ART_STYLES['circuit_board'])
        except ImportError:
            # Fallback symbols
            style_config = {
                'border_chars': '═║╔╗╚╝╦╩╠╣╬',
                'connection_chars': '─│┌┐└┘├┤┬┴┼',
                'node_chars': '●○◐◑◉',
                'flow_chars': '⚡⟐◀▶'
            }

        # Create symbol dictionary
        chars = style_config.get('border_chars', '═║╔╗╚╝╦╩╠╣╬')
        if len(chars) >= 10:
            return {
                'horizontal': chars[0],
                'vertical': chars[1],
                'top_left': chars[2],
                'top_right': chars[3],
                'bottom_left': chars[4],
                'bottom_right': chars[5],
                'cross': chars[6] if len(chars) > 6 else chars[0],
                't_down': chars[7] if len(chars) > 7 else chars[0],
                't_up': chars[8] if len(chars) > 8 else chars[0],
                't_right': chars[9] if len(chars) > 9 else chars[1],
                't_left': chars[0] if len(chars) > 10 else chars[1]
            }
        else:
            # Minimal fallback
            return {
                'horizontal': '=', 'vertical': '|',
                'top_left': '+', 'top_right': '+',
                'bottom_left': '+', 'bottom_right': '+',
                'cross': '+', 't_down': '+', 't_up': '+',
                't_right': '+', 't_left': '+'
            }

    @staticmethod
    def _get_styled_banner(style, target_display):
        """Get styled banner based on cyber theme"""
        if style == 'circuit_board':
            return AsciiArt._circuit_board_banner(target_display)
        elif style == 'security_lock':
            return AsciiArt._security_lock_banner(target_display)
        elif style == 'data_stream':
            return AsciiArt._data_stream_banner(target_display)
        else:
            return AsciiArt._circuit_board_banner(target_display)

    @staticmethod
    def _circuit_board_banner(target_display):
        """Circuit board style banner"""
        banner = f"""╔════════════════════════════════════════╗
║   ┌─[NPS]─┐    ╔═[TARGET]═╗         ║
║   │ ●─●─● │    ║ {target_display:<9} ║         ║
║   │ ●─⚡─● │    ╚═══════════╝         ║
║   └───╰───┘                       ║
║                                      ║
║   Network Pentesting Suite           ║
╚════════════════════════════════════════╝"""
        return colored(banner, 'tech_cyan', attrs=['bold'])

    @staticmethod
    def _security_lock_banner(target_display):
        """Security lock style banner"""
        banner = f"""╔════════════════════════════════════════╗
║   🔒 NPS TOOL 🔒                     ║
║   ┌─────────────────┐                ║
║   │  SECURE  SCAN  │                ║
║   │   🔐   LOCK    │                ║
║   │ Target: {target_display:<7} │                ║
║   └─────────────────┘                ║
║                                      ║
║   Network Security Assessment        ║
╚════════════════════════════════════════╝"""
        return colored(banner, 'cyber_purple', attrs=['bold'])

    @staticmethod
    def _data_stream_banner(target_display):
        """Data stream style banner"""
        banner = f"""╔════════════════════════════════════════╗
║  ▶ NPS TOOL ◀                        ║
║  ⟐⟐⟐⟐⟐⟐⟐⟐⟐⟐⟐⟐⟐                    ║
║  ▶ DATA STREAM: ████████████         ║
║  ◀ PACKETS: ⚡⚡⚡⚡⚡              ║
║                                      ║
║  Target: {target_display:<23}        ║
║  Network Security Analysis           ║
╚════════════════════════════════════════╝"""
        return colored(banner, 'electric_blue', attrs=['bold'])

    @staticmethod
    def multi_panel_banner(target=None, terminal_width=70):
        """Multi-panel dashboard-style header with multiple sections"""
        target_display = target if target else "Not Set"
        public_ip = AsciiArt.get_public_ip()

        # Adjust sections based on available width
        if terminal_width >= 100:
            return AsciiArt._large_multi_panel(target_display, public_ip)
        elif terminal_width >= 70:
            return AsciiArt._medium_multi_panel(target_display, public_ip)
        else:
            return AsciiArt._small_multi_panel(target_display, public_ip)

    @staticmethod
    def _large_multi_panel(target_display, public_ip):
        """Large multi-panel banner for wide terminals"""
        left_panel = f"""╔════════════════════╗
║ ⚡ NPS TOOL       ║
║ Network Security  ║
║ Suite v2.0        ║
╚════════════════════╝"""

        center_panel = f"""╔══════════════════════════════╗
║     CYBERSECURITY TESTING      ║
║  ╔═════════════════════════╗    ║
║  │ Target: {target_display:<13} │    ║
║  │ IP: {public_ip:<17} │    ║
║  ╚═════════════════════════╝    ║
╚══════════════════════════════╝"""

        right_panel = f"""╔════════════════════╗
║ ● SYSTEM READY     ║
║ 🔒 SECURE MODE     ║
║ 📡 NETWORK ACTIVE  ║
╚════════════════════╝"""

        # Combine panels with spacing
        banner = f"{colored(left_panel, 'tech_cyan')}   {colored(center_panel, 'cyber_purple')}   {colored(right_panel, 'enhanced_green')}"
        return banner

    @staticmethod
    def _medium_multi_panel(target_display, public_ip):
        """Medium multi-panel banner for standard terminals"""
        top_panel = f"""╔════════════════════════════════════════╗
║ ⚡ NPS TOOL - Network Security Suite v2.0    ║
╚════════════════════════════════════════╝"""

        bottom_panel = f"""╔════════════════════════════════════════╗
║ Target: {target_display:<33} IP: {public_ip:<15} ║
║ Status: ● Ready | 🔒 Secure | 📡 Connected   ║
╚════════════════════════════════════════╝"""

        return f"{colored(top_panel, 'tech_cyan', attrs=['bold'])}\n{colored(bottom_panel, 'cyber_purple')}"

    @staticmethod
    def _small_multi_panel(target_display, public_ip):
        """Compact multi-panel banner for small terminals"""
        banner = f"""╔══════════════════════════════════╗
║ ⚡ NPS TOOL - Network Security     ║
║ Target: {target_display:<19}        ║
║ IP: {public_ip:<23}              ║
║ Status: ● Ready | 🔒 Secure        ║
╚══════════════════════════════════╝"""
        return colored(banner, 'tech_cyan', attrs=['bold'])

    @staticmethod
    def size_presets(terminal_width=None, terminal_height=None):
        """Generate different banner sizes based on terminal dimensions"""
        import shutil

        if terminal_width is None or terminal_height is None:
            try:
                size = shutil.get_terminal_size()
                terminal_width = size.columns
                terminal_height = size.lines
            except:
                terminal_width = 80
                terminal_height = 24

        if terminal_width < 80 or terminal_height < 24:
            return 'small'
        elif terminal_width <= 120 and terminal_height <= 30:
            return 'medium'
        else:
            return 'large'

    @staticmethod
    def animated_progress_indicator(current, total, width=50, style='circuit'):
        """Enhanced progress bar with cyber-themed animations"""
        if total == 0:
            progress = 0.0
        else:
            progress = min(1.0, current / total)

        filled_width = int(progress * width)

        # Choose characters based on style
        if style == 'circuit':
            filled_char = '●'
            empty_char = '○'
            flow_char = '⚡'
        elif style == 'security':
            filled_char = '🔒'
            empty_char = '○'
            flow_char = '🛡️'
        elif style == 'data':
            filled_char = '█'
            empty_char = '░'
            flow_char = '⟐'
        else:
            filled_char = '█'
            empty_char = '░'
            flow_char = '▓'

        # Build progress bar
        bar = filled_char * filled_width + empty_char * (width - filled_width)

        # Add flow indicator if not complete
        if progress < 1.0 and filled_width < width:
            flow_pos = min(filled_width, width - 1)
            bar = bar[:flow_pos] + flow_char + bar[flow_pos + 1:]

        # Color based on progress
        if progress < 0.3:
            color = 'red'
        elif progress < 0.7:
            color = 'yellow'
        else:
            color = 'green'

        percentage = f"{progress * 100:.1f}%"
        return f"[{colored(bar, color)}] {colored(percentage, color)}"

    @staticmethod
    def status_indicators(status='ready', details=""):
        """Status indicators for different scan and tool execution phases"""
        status_configs = {
            'ready': {'symbol': '●', 'color': 'green', 'text': 'Ready'},
            'scanning': {'symbol': '⟳', 'color': 'yellow', 'text': 'Scanning'},
            'analyzing': {'symbol': '🔬', 'color': 'cyan', 'text': 'Analyzing'},
            'complete': {'symbol': '✓', 'color': 'green', 'text': 'Complete'},
            'error': {'symbol': '✗', 'color': 'red', 'text': 'Error'},
            'connecting': {'symbol': '📡', 'color': 'yellow', 'text': 'Connecting'},
            'connected': {'symbol': '🔗', 'color': 'green', 'text': 'Connected'},
            'warning': {'symbol': '⚠', 'color': 'yellow', 'text': 'Warning'},
            'security': {'symbol': '🔒', 'color': 'cyan', 'text': 'Secured'},
            'vulnerable': {'symbol': '⚡', 'color': 'red', 'text': 'Vulnerable'}
        }

        config = status_configs.get(status, status_configs['ready'])
        symbol = colored(config['symbol'], config['color'], attrs=['bold'])
        text = colored(config['text'], config['color'])

        if details:
            details_text = colored(f" - {details}", 'white')
            return f"{symbol} {text}{details_text}"
        else:
            return f"{symbol} {text}"

    @staticmethod
    def cyber_borders(width=50, height=10, style='circuit_board'):
        """Create cyber-themed border boxes"""
        try:
            from config import ASCII_ART_STYLES
            style_config = ASCII_ART_STYLES.get(style, ASCII_ART_STYLES['circuit_board'])
        except ImportError:
            style_config = {
                'border_chars': '═║╔╗╚╝╦╩╠╣╬',
                'connection_chars': '─│┌┐└┘├┤┬┴┼',
                'node_chars': '●○◐◑◉',
                'flow_chars': '⚡⟐◀▶'
            }

        chars = style_config.get('border_chars', '═║╔╗╚╝╦╩╠╣╬')
        if len(chars) >= 6:
            h, v, tl, tr, bl, br = chars[0], chars[1], chars[2], chars[3], chars[4], chars[5]
        else:
            h, v, tl, tr, bl, br = '═', '║', '╔', '╗', '╚', '╝'

        # Create top border
        top_border = tl + h * (width - 2) + tr

        # Create middle section
        middle_lines = []
        for i in range(height - 2):
            if i == height // 2 - 1:  # Add decoration in middle
                decoration = " ⚡ CYBER ⚡ "
                padding = (width - 2 - len(decoration)) // 2
                middle_line = v + " " * padding + decoration + " " * (width - 2 - len(decoration) - padding) + v
            else:
                middle_line = v + " " * (width - 2) + v
            middle_lines.append(middle_line)

        # Create bottom border
        bottom_border = bl + h * (width - 2) + br

        # Combine all parts
        box_lines = [top_border] + middle_lines + [bottom_border]
        return '\n'.join([colored(line, 'tech_cyan') for line in box_lines])

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
