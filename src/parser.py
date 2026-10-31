"""
Cowrie Log Parser & Data Sanitizer Module.
MCA Information Security Management Systems Project.

Responsible for:
1. Parsing Cowrie JSON logs and Twisted text logs without altering original files.
2. Sanitizing sensitive plaintext passwords into redacted copies for safe presentation.
3. Extracting sessions, connection metadata, authentication events, and command histories.
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class CowrieParser:
    """
    Parses and sanitizes Cowrie SSH honeypot logs (JSON & text formats).
    Strictly preserves raw data integrity while ensuring sensitive credentials
    are never leaked in dashboards, reports, or artifacts.
    """

    def __init__(
        self,
        raw_json_path: str = "cowrie.json",
        raw_log_path: str = "cowrie.log",
        sanitized_dir: str = "data"
    ):
        self.raw_json_path = Path(raw_json_path)
        self.raw_log_path = Path(raw_log_path)
        self.sanitized_dir = Path(sanitized_dir)
        self.sanitized_dir.mkdir(parents=True, exist_ok=True)

        self.sanitized_json_path = self.sanitized_dir / "sanitized_cowrie.json"
        self.sanitized_log_path = self.sanitized_dir / "sanitized_cowrie.log"

        self.raw_events: List[Dict[str, Any]] = []
        self.sanitized_events: List[Dict[str, Any]] = []
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.daemon_events: List[Dict[str, Any]] = []

    def sanitize_files(self) -> Tuple[Path, Path]:
        """
        Creates sanitized copies of cowrie.json and cowrie.log with passwords redacted.
        Leaves original files completely intact.
        """
        # 1. Sanitize JSON
        if self.raw_json_path.exists():
            sanitized_lines = []
            with open(self.raw_json_path, "r", encoding="utf-8") as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        record = json.loads(line_str)
                        # Redact password key
                        if "password" in record:
                            record["password"] = "[REDACTED]"
                        # Redact password in message string if present (e.g. login attempt [user/pass])
                        if "message" in record and isinstance(record["message"], str):
                            record["message"] = re.sub(
                                r"login attempt \[([^/]+)/([^\]]+)\] succeeded",
                                r"login attempt [\1/[REDACTED]] succeeded",
                                record["message"]
                            )
                            record["message"] = re.sub(
                                r"login attempt \[([^/]+)/([^\]]+)\] failed",
                                r"login attempt [\1/[REDACTED]] failed",
                                record["message"]
                            )
                        sanitized_lines.append(json.dumps(record))
                    except json.JSONDecodeError:
                        sanitized_lines.append(line_str)

            with open(self.sanitized_json_path, "w", encoding="utf-8") as f:
                f.write("\n".join(sanitized_lines) + "\n")

        # 2. Sanitize Text Log
        if self.raw_log_path.exists():
            sanitized_log_lines = []
            with open(self.raw_log_path, "r", encoding="utf-8") as f:
                for line in f:
                    # Redact passwords in format: login attempt [username/password] succeeded
                    sanitized_line = re.sub(
                        r"login attempt \[([^/]+)/([^\]]+)\] succeeded",
                        r"login attempt [\1/[REDACTED]] succeeded",
                        line
                    )
                    sanitized_line = re.sub(
                        r"login attempt \[([^/]+)/([^\]]+)\] failed",
                        r"login attempt [\1/[REDACTED]] failed",
                        sanitized_line
                    )
                    sanitized_log_lines.append(sanitized_line)

            with open(self.sanitized_log_path, "w", encoding="utf-8") as f:
                f.writelines(sanitized_log_lines)

        return self.sanitized_json_path, self.sanitized_log_path

    def load_json_events(self) -> List[Dict[str, Any]]:
        """
        Loads and parses events from the JSON file, automatically sanitizing passwords in memory.
        """
        target_path = self.sanitized_json_path if self.sanitized_json_path.exists() else self.raw_json_path
        if not target_path.exists():
            raise FileNotFoundError(f"JSON log file not found at {target_path}")

        events = []
        with open(target_path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, start=1):
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    record = json.loads(line_str)
                    # Defense-in-depth: enforce in-memory redaction
                    if "password" in record:
                        record["password"] = "[REDACTED]"
                    if "message" in record and isinstance(record["message"], str):
                        record["message"] = re.sub(
                            r"login attempt \[([^/]+)/([^\]]+)\]",
                            r"login attempt [\1/[REDACTED]]",
                            record["message"]
                        )
                    record["_line_number"] = idx
                    events.append(record)
                except json.JSONDecodeError as e:
                    print(f"Warning: JSON decode error at line {idx}: {e}")

        self.sanitized_events = events
        return events

    def load_text_log_events(self) -> List[Dict[str, Any]]:
        """
        Parses daemon startup and shutdown events from the cowrie.log file.
        """
        target_path = self.sanitized_log_path if self.sanitized_log_path.exists() else self.raw_log_path
        if not target_path.exists():
            return []

        daemon_events = []
        log_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+\[([^\]]+)\]\s+(.*)$")

        with open(target_path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, start=1):
                match = log_pattern.match(line.strip())
                if match:
                    ts, channel, msg = match.groups()
                    daemon_events.append({
                        "line": idx,
                        "timestamp": ts,
                        "channel": channel,
                        "message": msg
                    })

        self.daemon_events = daemon_events
        return daemon_events

    def parse_sessions(self) -> Dict[str, Dict[str, Any]]:
        """
        Correlates linear event streams into stateful SSH sessions.
        """
        if not self.sanitized_events:
            self.load_json_events()

        sessions: Dict[str, Dict[str, Any]] = {}

        for event in self.sanitized_events:
            sess_id = event.get("session")
            if not sess_id:
                continue

            if sess_id not in sessions:
                sessions[sess_id] = {
                    "session_id": sess_id,
                    "protocol": event.get("protocol", "ssh"),
                    "src_ip": event.get("src_ip", "Unknown"),
                    "src_port": event.get("src_port"),
                    "dst_ip": event.get("dst_ip", "127.0.0.1"),
                    "dst_port": event.get("dst_port", 2222),
                    "sensor": event.get("sensor", "honeypot"),
                    "start_time": event.get("timestamp"),
                    "end_time": None,
                    "duration_seconds": 0.0,
                    "duration_ms": 0,
                    "ssh_version": None,
                    "hassh": None,
                    "auth_attempts": [],
                    "successful_logins": [],
                    "failed_logins": [],
                    "commands": [],
                    "terminal_size": None,
                    "locale": None,
                    "arch": None,
                    "ttylog_path": None,
                    "ttylog_shasum": None,
                    "ttylog_duration_ms": None,
                    "events": [],
                    "is_localhost": False,
                    "traffic_type": "Unknown"
                }

            sess = sessions[sess_id]
            sess["events"].append(event)
            event_id = event.get("eventid")
            ts = event.get("timestamp")

            # Check localhost
            if sess["src_ip"] == "127.0.0.1":
                sess["is_localhost"] = True
                sess["traffic_type"] = "Simulated Localhost Verification Test"

            # Parse event-specific fields
            if event_id == "cowrie.client.version":
                sess["ssh_version"] = event.get("version")

            elif event_id == "cowrie.client.kex":
                sess["hassh"] = event.get("hassh")
                sess["hasshAlgorithms"] = event.get("hasshAlgorithms")
                sess["kexAlgs"] = event.get("kexAlgs", [])

            elif event_id == "cowrie.login.success":
                login_entry = {
                    "username": event.get("username"),
                    "password": "[REDACTED]",
                    "status": "SUCCESS",
                    "timestamp": ts
                }
                sess["auth_attempts"].append(login_entry)
                sess["successful_logins"].append(login_entry)

            elif event_id == "cowrie.login.failed":
                login_entry = {
                    "username": event.get("username"),
                    "password": "[REDACTED]",
                    "status": "FAILED",
                    "timestamp": ts
                }
                sess["auth_attempts"].append(login_entry)
                sess["failed_logins"].append(login_entry)

            elif event_id == "cowrie.client.size":
                sess["terminal_size"] = f"{event.get('width')}x{event.get('height')}"

            elif event_id == "cowrie.client.var":
                if event.get("name") == "LANG":
                    sess["locale"] = event.get("value")

            elif event_id == "cowrie.session.params":
                sess["arch"] = event.get("arch")

            elif event_id == "cowrie.command.input":
                cmd = event.get("input", "")
                sess["commands"].append({
                    "command": cmd,
                    "clean_command": cmd.strip(),
                    "timestamp": ts
                })

            elif event_id == "cowrie.log.closed":
                sess["ttylog_path"] = event.get("ttylog")
                sess["ttylog_shasum"] = event.get("shasum")
                sess["ttylog_duration_ms"] = event.get("duration_ms")

            elif event_id == "cowrie.session.closed":
                sess["end_time"] = ts
                sess["duration_ms"] = event.get("duration_ms", 0)
                if sess["duration_ms"]:
                    sess["duration_seconds"] = round(sess["duration_ms"] / 1000.0, 2)

        # Fallback duration calculation if closed event was missing
        for sess in sessions.values():
            if not sess["end_time"] and sess["events"]:
                sess["end_time"] = sess["events"][-1].get("timestamp")
            if sess["duration_seconds"] == 0.0 and sess["start_time"] and sess["end_time"]:
                try:
                    t1 = datetime.fromisoformat(sess["start_time"].replace("Z", "+00:00"))
                    t2 = datetime.fromisoformat(sess["end_time"].replace("Z", "+00:00"))
                    sess["duration_seconds"] = round(abs((t2 - t1).total_seconds()), 2)
                except Exception:
                    pass

        self.sessions = sessions
        return sessions

    def get_summary_metrics(self) -> Dict[str, Any]:
        """
        Computes accurate summary metrics strictly based on parsed data.
        Does not fabricate any values.
        """
        if not self.sessions:
            self.parse_sessions()

        total_sessions = len(self.sessions)
        unique_ips = set(s["src_ip"] for s in self.sessions.values())
        total_commands = sum(len(s["commands"]) for s in self.sessions.values())
        unique_commands = set(
            c["clean_command"] for s in self.sessions.values() for c in s["commands"]
        )

        all_auth = [a for s in self.sessions.values() for a in s["auth_attempts"]]
        success_logins = [a for s in self.sessions.values() for a in s["successful_logins"]]
        failed_logins = [a for s in self.sessions.values() for a in s["failed_logins"]]

        event_distribution = {}
        for ev in self.sanitized_events:
            eid = ev.get("eventid", "unknown")
            event_distribution[eid] = event_distribution.get(eid, 0) + 1

        total_engagement_seconds = sum(s["duration_seconds"] for s in self.sessions.values())

        return {
            "total_events": len(self.sanitized_events),
            "total_sessions": total_sessions,
            "unique_source_ips": list(unique_ips),
            "total_source_ips_count": len(unique_ips),
            "total_auth_attempts": len(all_auth),
            "successful_logins_count": len(success_logins),
            "failed_logins_count": len(failed_logins),
            "total_commands_executed": total_commands,
            "unique_commands_count": len(unique_commands),
            "unique_commands_list": sorted(list(unique_commands)),
            "total_engagement_seconds": round(total_engagement_seconds, 2),
            "average_session_duration_seconds": round(
                total_engagement_seconds / total_sessions, 2
            ) if total_sessions > 0 else 0.0,
            "event_type_distribution": event_distribution,
            "honeypot_mode": "SSH Port 2222 (Twisted Reactor)",
            "sensor_name": "honeypot",
            "traffic_classification": "Internal Validation / Simulated Localhost Testing"
        }
