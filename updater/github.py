"""GitHub auto-update system"""

import os
import sys
import datetime
import subprocess
import shutil
from utils.printer import Printer


class GitHubUpdater:
    """Handles automatic updates from GitHub repository"""

    @staticmethod
    def check_update():
        """Check and apply updates from GitHub repository with conflict resolution"""
        try:
            if not os.path.exists('.git'):
                Printer.warning("Auto-update disabled (not a git repo)")
                return False

            # Check remote status
            fetch_result = subprocess.run(['git', 'fetch', 'origin'],
                                        capture_output=True, text=True)
            if fetch_result.returncode != 0:
                raise Exception(fetch_result.stderr)

            # Get commit hashes
            local_hash = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip()
            remote_hash = subprocess.check_output(['git', 'rev-parse', 'origin/main']).decode().strip()

            if local_hash == remote_hash:
                return False

            Printer.success(f"New version available ({remote_hash[:7]})")

            # Check for local modifications
            status_result = subprocess.run(['git', 'status', '--porcelain'],
                                         capture_output=True, text=True)
            has_changes = bool(status_result.stdout.strip())

            if has_changes:
                # Create backup of modified files
                backup_dir = f"backup_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
                os.makedirs(backup_dir, exist_ok=True)

                # Copy modified files and directories properly
                for line in status_result.stdout.splitlines():
                    # Extract filename from git status output
                    file_path = line[3:].strip()
                    if os.path.exists(file_path):
                        dest_path = os.path.join(backup_dir, file_path)
                        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                        if os.path.isdir(file_path):
                            shutil.copytree(file_path, dest_path, dirs_exist_ok=True)
                        else:
                            shutil.copy2(file_path, dest_path)

                Printer.warning(f"Local changes backed up to {backup_dir}/")

                # Reset to remote state
                reset_result = subprocess.run(['git', 'reset', '--hard', 'origin/main'],
                                            capture_output=True, text=True)
                if reset_result.returncode != 0:
                    raise Exception(reset_result.stderr)
            else:
                # Regular fast-forward merge
                pull_result = subprocess.run(['git', 'pull', '--ff-only', 'origin', 'main'],
                                           capture_output=True, text=True)
                if pull_result.returncode != 0:
                    raise Exception(pull_result.stderr)

            Printer.success("Update successful! Restart required")
            return True

        except Exception as e:
            Printer.error(f"Update failed: {str(e)}")
            return False
