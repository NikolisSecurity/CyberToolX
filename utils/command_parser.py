"""Command parser with auto-correction and fuzzy matching"""

import difflib
from .color_compat import colored


class CommandParser:
    """Parse and auto-correct user commands"""

    def __init__(self, valid_commands):
        """
        Initialize command parser.

        Args:
            valid_commands: Dictionary of valid commands and their descriptions
        """
        self.valid_commands = valid_commands
        self.command_list = list(valid_commands.keys())

    def parse(self, user_input):
        """
        Parse user input and auto-correct if needed.

        Args:
            user_input: Raw user input string

        Returns:
            tuple: (corrected_command, args_list) or (None, None) if invalid
        """
        if not user_input or not user_input.strip():
            return None, None

        parts = user_input.strip().split()
        command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []

        # Check if command is valid
        if command in self.command_list:
            return command, args

        # Try to find close matches
        close_matches = difflib.get_close_matches(command, self.command_list, n=3, cutoff=0.6)

        if close_matches:
            # Show simple error message without suggestions
            print(f'\nCommand "{command}" is not valid.')
            return None, None
        else:
            print(f'\nCommand "{command}" is not valid.')
            return None, None

    def suggest_commands(self, prefix):
        """
        Suggest commands that start with the given prefix.

        Args:
            prefix: Command prefix to match

        Returns:
            list: List of matching commands
        """
        if not prefix:
            return self.command_list

        matches = [cmd for cmd in self.command_list if cmd.startswith(prefix.lower())]
        return matches

    def get_command_info(self, command):
        """
        Get detailed information about a command.

        Args:
            command: Command name

        Returns:
            str: Command description or None
        """
        return self.valid_commands.get(command)
