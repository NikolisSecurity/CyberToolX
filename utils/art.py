"""ASCII art banner for CyberGuardian Ultimate"""

from termcolor import colored


class SecurityArt:
    @staticmethod
    def banner(version='2.0'):
        """Display ASCII art banner with version"""
        from config import CONFIG
        return f"""
        {colored('''
       ██████╗██╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
      ██╔════╝╚██╗ ██╔╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
      ██║      ╚████╔╝ ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
      ██║       ╚██╔╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
      ╚██████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
       ╚═════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝

        ''', CONFIG['banner_color'])}
        {colored(f'CyberGuardian Ultimate v{version}', CONFIG['highlight_color'], attrs=['bold'])}
        """
