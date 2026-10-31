"""
MITRE ATT&CK Framework Mapping Module.
MCA Information Security Management Systems Project.

Maps observed Cowrie honeypot events and commands to MITRE ATT&CK Enterprise Matrix
tactics and techniques, supporting rigorous academic threat analysis and defense.
"""

from typing import Any, Dict, List


class MitreMapper:
    """
    Correlates honeypot observations with MITRE ATT&CK Enterprise Matrix (v14+).
    """

    TECHNIQUE_CATALOG = {
        "T1078": {
            "id": "T1078",
            "tactic": "Initial Access / Persistence / Privilege Escalation / Defense Evasion",
            "tactic_id": "TA0001",
            "name": "Valid Accounts",
            "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
            "url": "https://attack.mitre.org/techniques/T1078/"
        },
        "T1110.001": {
            "id": "T1110.001",
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "name": "Brute Force: Password Guessing",
            "description": "Adversaries with no prior knowledge of passwords may attempt to guess passwords to gain access to accounts.",
            "url": "https://attack.mitre.org/techniques/T1110/001/"
        },
        "T1059.004": {
            "id": "T1059.004",
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "name": "Command and Scripting Interpreter: Unix Shell",
            "description": "Adversaries may abuse Unix shell interpreters (bash, sh) to execute arbitrary commands or interactive shell scripts.",
            "url": "https://attack.mitre.org/techniques/T1059/004/"
        },
        "T1033": {
            "id": "T1033",
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "name": "System Owner/User Discovery",
            "description": "Adversaries may attempt to identify the primary user, currently logged-in user, or system administrator privileges.",
            "url": "https://attack.mitre.org/techniques/T1033/"
        },
        "T1082": {
            "id": "T1082",
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "name": "System Information Discovery",
            "description": "Adversaries may attempt to get detailed information about the operating system and hardware, including version, architecture, and hostname.",
            "url": "https://attack.mitre.org/techniques/T1082/"
        },
        "T1083": {
            "id": "T1083",
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "name": "File and Directory Discovery",
            "description": "Adversaries may enumerate files and directories or search in specific locations of the host filesystem.",
            "url": "https://attack.mitre.org/techniques/T1083/"
        }
    }

    COMMAND_MAPPINGS = {
        "whoami": {
            "technique_id": "T1033",
            "name": "System Owner/User Discovery",
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "rationale": "Verifies current user identity and privilege level (evaluating if root/superuser permissions are available)."
        },
        "hostname": {
            "technique_id": "T1082",
            "name": "System Information Discovery",
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "rationale": "Identifies the host computer name, network naming conventions, and domain role."
        },
        "pwd": {
            "technique_id": "T1083",
            "name": "File and Directory Discovery",
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "rationale": "Discovers current working directory context within the honeypot virtual filesystem."
        },
        "ls": {
            "technique_id": "T1083",
            "name": "File and Directory Discovery",
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "rationale": "Enumerates directory contents, looking for sensitive files, source code, scripts, or readable credentials."
        },
        "exit": {
            "technique_id": "T1059.004",
            "name": "Interactive Shell Termination",
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "rationale": "Terminates the interactive session cleanly."
        }
    }

    @classmethod
    def map_command(cls, raw_command: str) -> Dict[str, Any]:
        """Maps an individual command to MITRE ATT&CK technique."""
        clean_cmd = raw_command.strip()
        base_cmd = clean_cmd.split()[0] if clean_cmd else ""

        if base_cmd in cls.COMMAND_MAPPINGS:
            mapping = cls.COMMAND_MAPPINGS[base_cmd].copy()
            mapping["raw_command"] = raw_command
            mapping["catalog_entry"] = cls.TECHNIQUE_CATALOG.get(mapping["technique_id"])
            return mapping

        return {
            "technique_id": "T1059.004",
            "name": "Command and Scripting Interpreter: Unix Shell",
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "rationale": f"Uncategorized command '{raw_command}' executed via Unix shell interpreter.",
            "raw_command": raw_command,
            "catalog_entry": cls.TECHNIQUE_CATALOG.get("T1059.004")
        }

    @classmethod
    def map_session_events(cls, session: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Maps all tactical actions within an SSH session to MITRE ATT&CK."""
        mappings = []

        # 1. Authentication event mapping
        for auth in session.get("auth_attempts", []):
            if auth.get("status") == "SUCCESS":
                mappings.append({
                    "event_type": "Authentication",
                    "timestamp": auth.get("timestamp"),
                    "technique_id": "T1078",
                    "technique_name": "Valid Accounts",
                    "tactic": "Initial Access",
                    "tactic_id": "TA0001",
                    "details": f"Successful login with username '{auth.get('username')}' (credentials accepted by honeypot).",
                    "evidence": f"Username: {auth.get('username')}, Status: {auth.get('status')}"
                })

        # 2. PTY/Shell request mapping
        if session.get("terminal_size"):
            mappings.append({
                "event_type": "Interactive Shell Allocation",
                "timestamp": session.get("start_time"),
                "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Unix Shell",
                "tactic": "Execution",
                "tactic_id": "TA0002",
                "details": f"Allocated PTY terminal size {session.get('terminal_size')} with locale {session.get('locale')}.",
                "evidence": f"Terminal: {session.get('terminal_size')}, Arch: {session.get('arch')}"
            })

        # 3. Command execution mapping
        for cmd_entry in session.get("commands", []):
            cmd = cmd_entry.get("command", "")
            mapped = cls.map_command(cmd)
            mappings.append({
                "event_type": "Command Execution",
                "timestamp": cmd_entry.get("timestamp"),
                "technique_id": mapped["technique_id"],
                "technique_name": mapped["name"],
                "tactic": mapped["tactic"],
                "tactic_id": mapped["tactic_id"],
                "details": mapped["rationale"],
                "evidence": f"Command: {cmd}"
            })

        return mappings
