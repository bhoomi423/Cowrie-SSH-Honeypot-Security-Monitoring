"""
Automated Artifact & Report Generator Pipeline.
MCA Information Security Management Systems Project.

Executes complete data pipeline headlessly:
1. Log Sanitization & Verification
2. Statistical Metrics & Session Aggregation
3. Threat Analysis & MITRE ATT&CK Mapping
4. ISO 27001:2022 Control Mapping & Risk Matrix Generation
5. Publication-Quality Chart Rendering
6. Integration of Student Lab Implementation Evidence (20 Screenshots)
7. Comprehensive Final Academic Security Analysis Report
"""

import os
import sys
import tempfile
from pathlib import Path

# Ensure Matplotlib uses a valid writable temporary config directory
os.environ["MPLCONFIGDIR"] = os.path.join(tempfile.gettempdir(), "matplotlib")

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.parser import CowrieParser
from src.analyzer import ThreatAnalyzer
from src.visualizer import SecurityVisualizer
from src.mitre_mapper import MitreMapper
from src.iso27001_risk import ISO27001RiskManager


def generate_all():
    print("[+] Step 1: Initializing Parser & Sanitizing Log Files...")
    parser = CowrieParser(
        raw_json_path=str(PROJECT_ROOT / "cowrie.json"),
        raw_log_path=str(PROJECT_ROOT / "cowrie.log"),
        sanitized_dir=str(PROJECT_ROOT / "data")
    )
    s_json, s_log = parser.sanitize_files()
    print(f"    - Sanitized JSON written to: {s_json}")
    print(f"    - Sanitized Log written to:  {s_log}")

    print("[+] Step 2: Ingesting & Correlating Telemetry Events...")
    parser.load_json_events()
    parser.load_text_log_events()
    sessions = parser.parse_sessions()
    metrics = parser.get_summary_metrics()
    print(f"    - Processed {metrics['total_events']} events across {metrics['total_sessions']} sessions.")
    print(f"    - Unique source IPs: {metrics['unique_source_ips']}")
    print(f"    - Total login attempts: {metrics['total_auth_attempts']} (Success: {metrics['successful_logins_count']}, Failed: {metrics['failed_logins_count']})")
    print(f"    - Total commands: {metrics['total_commands_executed']}")

    print("[+] Step 3: Executing Behavioral & Threat Analytics...")
    analyzer = ThreatAnalyzer(sessions, metrics)
    threat_info = analyzer.perform_threat_classification()
    timelines = analyzer.build_session_timelines()
    commands_data = analyzer.get_command_analysis()
    mitre_events = [ev for s in sessions.values() for ev in MitreMapper.map_session_events(s)]
    print(f"    - Traffic Classified as: {threat_info['traffic_classification']}")

    print("[+] Step 4: Generating Security Visualizations & Charts...")
    charts_dir = PROJECT_ROOT / "dashboard" / "static" / "images"
    visualizer = SecurityVisualizer(output_dir=str(charts_dir))
    chart_paths = visualizer.generate_all_charts(metrics, commands_data, sessions, mitre_events)
    for name, path in chart_paths.items():
        print(f"    - Chart '{name}': {path}")

    print("[+] Step 5: Compiling Comprehensive Security Analysis Report with Evidence...")
    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "security_analysis_report.md"

    iso_controls = ISO27001RiskManager.get_iso_mappings()
    risk_matrix = ISO27001RiskManager.get_risk_assessment_matrix()
    disclaimer = ISO27001RiskManager.get_compliance_disclaimer()

    # Build Markdown Report
    report_lines = [
        "# SSH Honeypot Monitoring and Security Analysis Using Cowrie",
        "## Practical Cybersecurity Project Report",
        "**Degree Program:** Master of Computer Applications (MCA)  ",
        "**Specialization:** Information Security Management Systems (ISMS)  ",
        "**Target Environment:** VMware Workstation Pro 17 | Ubuntu Server 24.04.5 LTS | Cowrie SSH Honeypot | Python 3  ",
        f"**Sensor UUID:** `{parser.sanitized_events[0].get('uuid', 'b87bf595-d41c-11f1-83af-000c296f4a56')}` | **Sensor Mode:** SSH on Port 2222  ",
        "**Data Confidentiality Notice:** All sensitive passwords have been sanitized and redacted (`[REDACTED]`). Original raw logs preserved intact.",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "This project establishes a security monitoring, threat intelligence, and compliance assessment solution based on telemetry captured by a Cowrie SSH Honeypot. Cowrie was deployed on an Ubuntu Server 24.04 virtual machine within VMware Workstation Pro 17 to emulate a high-value UNIX SSH server and intercept unauthorized access attempts.",
        "",
        "During the operational monitoring window, two distinct SSH interaction sessions were captured. Detailed analysis reveals that both sessions originated from the local loopback interface (`127.0.0.1`), demonstrating controlled internal verification and smoke-testing rather than external threat actor incursions. All authentication attempts succeeded due to Cowrie's default credential ingestion policy. The first session contained interactive reconnaissance commands (`whoami`, `hostname`, `pwd`, `ls`, `exit`), while the second session terminated immediately after authentication.",
        "",
        "A modular Python security architecture was developed to parse raw JSON and Twisted logs, calculate session state metrics, map adversary tactics to the MITRE ATT&CK framework, align technical detective capabilities with ISO/IEC 27001:2022 Annex A controls, and perform a formal ISMS 5x5 qualitative risk assessment.",
        "",
        "### Key Quantitative Metrics",
        f"- **Total Ingested Log Events:** {metrics['total_events']}",
        f"- **Total Monitored Sessions:** {metrics['total_sessions']}",
        f"- **Unique Source IP Addresses:** {metrics['total_source_ips_count']} (`{metrics['unique_source_ips'][0]}` - Loopback Interface)",
        f"- **Total Authentication Attempts:** {metrics['total_auth_attempts']}",
        f"- **Successful Authentication Events:** {metrics['successful_logins_count']} (100% success rate under Cowrie evaluation mode)",
        f"- **Failed Authentication Events:** {metrics['failed_logins_count']}",
        f"- **Total Executed Shell Commands:** {metrics['total_commands_executed']} ({metrics['unique_commands_count']} unique: `exit`, `hostname`, `ls`, `pwd`, `whoami`)",
        f"- **Total Engagement Duration:** {metrics['total_engagement_seconds']} seconds (~6 minutes 13 seconds)",
        f"- **Average Session Duration:** {metrics['average_session_duration_seconds']} seconds",
        "",
        "---",
        "",
        "## 2. Architecture & Operational Workflow",
        "The project architecture separates detection, ingestion, parsing, sanitization, analysis, and presentation into decoupled layers:",
        "",
        "```",
        "+-------------------------------------------------------------------------+",
        "|                     DECEPTION SENSOR LAYER                             |",
        "|  Ubuntu Server 24.04 (VMware Pro 17) -> Cowrie SSH Honeypot (Port 2222) |",
        "+-------------------------------------------------------------------------+",
        "                                     |",
        "                                     v",
        "+-------------------------------------------------------------------------+",
        "|                       RAW TELEMETRY STORAGE                             |",
        "|  - cowrie.json (Structured JSON-L)   - cowrie.log (Twisted Text Logs)   |",
        "+-------------------------------------------------------------------------+",
        "                                     |",
        "                                     v",
        "+-------------------------------------------------------------------------+",
        "|                   PARSING & SANITIZATION LAYER                          |",
        "|  - CowrieParser (src/parser.py)                                         |",
        "|  - Preserves originals; generates data/sanitized_cowrie.*               |",
        "|  - Redacts plaintext passwords to [REDACTED] in memory and storage      |",
        "+-------------------------------------------------------------------------+",
        "                                     |",
        "                  +------------------+------------------+",
        "                  |                                     |",
        "                  v                                     v",
        "+------------------------------------+ +----------------------------------+",
        "|     THREAT & BEHAVIORAL ANALYZER   | |    COMPLIANCE & RISK ENGINE      |",
        "| - ThreatAnalyzer (src/analyzer.py) | | - ISO27001RiskManager            |",
        "| - Session timeline construction    | |   (src/iso27001_risk.py)         |",
        "| - MITRE ATT&CK correlation         | | - ISO 27001:2022 Annex A Mapping |",
        "| - Localhost vs external heuristics | | - 5x5 ISMS Risk Assessment       |",
        "+------------------------------------+ +----------------------------------+",
        "                  |                                     |",
        "                  +------------------+------------------+",
        "                                     |",
        "                                     v",
        "+-------------------------------------------------------------------------+",
        "|                      VISUALIZATION & SOC DASHBOARD                      |",
        "|  - SecurityVisualizer (src/visualizer.py) -> High-Res Themed Charts     |",
        "|  - Flask SOC Dashboard (dashboard/app.py) -> Multi-view Web Console     |",
        "+-------------------------------------------------------------------------+",
        "```",
        "",
        "---",
        "",
        "## 3. Student Implementation Evidence & Lab Milestones",
        "",
        "The student conducted end-to-end practical deployment and verification in the VMware Workstation Pro 17 virtualized lab environment. Seven primary forensic evidence milestones were captured and archived in `evidence/` to corroborate each milestone:",
        "",
        "### Milestone 1: Host Environment & Network Setup (`evidence/01_vm_environment_and_ip.png`)",
        "Ubuntu Server 24.04.5 LTS guest OS splash screen running in VMware Workstation Pro 17, confirming IPv4 address `192.168.28.131` on virtual network adapter `ens33`.",
        "",
        "### Milestone 2: Cowrie Honeypot Authentication Configuration (`evidence/02_cowrie_auth_configuration.png`)",
        "Terminal inspection of `etc/cowrie.cfg` verifying `auth_class = UserDB` and demonstrating interactive exit from the honeypot's emulated shell.",
        "",
        "### Milestone 3: Authentication Fallback & Wildcard Rule (`evidence/03_userdb_wildcard_fallback.png`)",
        "Investigation of Cowrie's `userdb.example` showing the terminal wildcard rule `*:x:*`. When `userdb.txt` is absent, Cowrie's authentication engine (`src/cowrie/core/auth.py`) activates this default, explaining why `testuser` and `fakeuser` were accepted.",
        "",
        "### Milestone 4: Raw In-VM Telemetry Logs (`evidence/04_raw_log_files_in_vm.png`)",
        "Directory listing of `/home/cowrie/cowrie/var/log/cowrie/` inside Ubuntu confirming the existence, sizes, and timestamps of `cowrie.json` (13 KB) and `cowrie.log` (8.8 KB).",
        "",
        "### Milestone 5: In-VM Session Duration Calculation (`evidence/05_in_vm_session_duration.png`)",
        "Inline Python script running inside the Ubuntu VM calculating Session 1 duration as `0:03:24.442211` (~204.44 seconds) and verifying the `testuser` login event, matching our analytical parser exactly.",
        "",
        "### Milestone 6: In-VM Command Sequence Audit (`evidence/06_in_vm_command_audit.png`)",
        "Inline Python command parser output verifying the exact execution sequence and timestamps: `whoami`, `hostname`, `pwd`, `ls`, `ls`, and `exit`.",
        "",
        "### Milestone 7: Cross-Platform Forensic SCP Transfer (`evidence/07_scp_export_to_windows.png`)",
        "Windows PowerShell terminal session demonstrating folder creation and 100% transfer completion of `cowrie.json` (12 KB) and `cowrie.log` (8,922 bytes) from `labuser@192.168.28.131:/tmp/` into the Windows analysis workspace.",
        "",
        "---",
        "",
        "## 4. Session & Behavioral Telemetry Analysis",
        "",
        "### Session 1: `980210c2cbb3` (Interactive Reconnaissance)",
        "- **Connection Time:** `2026-10-30T04:54:00.138369Z`",
        "- **Disconnection Time:** `2026-10-30T04:57:24.580580Z`",
        "- **Duration:** `204.44` seconds (~3 minutes 24 seconds)",
        "- **Source Endpoint:** `127.0.0.1:41440` -> `127.0.0.1:2222`",
        "- **Client Banner:** `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`",
        "- **HASSH Fingerprint:** `aae6b9604f6f3356543709a376d7f657`",
        "- **Authenticated Identity:** `testuser` (Password: `[REDACTED]`)",
        "- **TTY Session Recording:** `var/lib/cowrie/tty/51b3d31ad1b7b3afcc6194f05ef575b82686aa82f43722ca5d0bc03d07685011`",
        "- **Observed Command Sequence:**",
        "  1. `whoami` (`04:55:21Z`) - Querying active user permissions.",
        "  2. `hostname` (`04:55:39Z`) - Enumerating host system identifier.",
        "  3. `pwd` (`04:56:05Z`) - Determining current directory location.",
        "  4. `ls` (`04:56:28Z`) - Listing home directory files.",
        "  5. `ls` (`04:56:38Z`) - Re-verifying directory listing.",
        "  6. `exit` (`04:57:24Z`) - Cleanly logging out.",
        "",
        "### Session 2: `87e196a90797` (Authentication Smoke-Test)",
        "- **Connection Time:** `2026-10-30T14:57:02.626910Z`",
        "- **Disconnection Time:** `2026-10-30T14:59:51.147867Z`",
        "- **Duration:** `168.51` seconds (~2 minutes 48 seconds)",
        "- **Source Endpoint:** `127.0.0.1:57560` -> `127.0.0.1:2222`",
        "- **Client Banner:** `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`",
        "- **HASSH Fingerprint:** `aae6b9604f6f3356543709a376d7f657`",
        "- **Authenticated Identity:** `fakeuser` (Password: `[REDACTED]`)",
        "- **TTY Session Recording:** `var/lib/cowrie/tty/076d0f83ea5ae0f758a8088a9dfe2b2510c4b78a283f0ad8bcafbff6a7e412fb`",
        "- **Observed Command Sequence:**",
        "  1. `exit ` (`14:59:51Z`) - Immediate terminal exit without issuing exploration commands.",
        "",
        "---",
        "",
        "## 5. Threat Analysis: Simulated Testing vs. Genuine External Attacks",
        "",
        "A critical requirement in security intelligence is ensuring that monitoring systems do not falsely mischaracterize benign administrative validation as external threat actor activity.",
        "",
        "| Evaluation Dimension | Observed Project Telemetry | Real-World External Attack Baseline | Analyst Conclusion |",
        "| :--- | :--- | :--- | :--- |",
        "| **Source IP & Routing** | `127.0.0.1` (Local Loopback) | Publicly routable IPs (Tor nodes, bulletproof hosters, residential proxies) | **Controlled Local Test:** Packets never traversed external internet gateways. |",
        "| **Authentication Frequency** | Exactly 2 logins across a 10-hour span | Automated credential stuffing: hundreds of attempts per second | **Manual Verification:** Human login pacing without brute-force dictionaries. |",
        "| **Authentication Outcome** | 100% Success (2/2) | Low success rates (<0.1%) against hardened targets | **Honeypot Acceptance:** Validates Cowrie's default configuration accepting test credentials. |",
        "| **Command Execution Pacing** | Human typing intervals (18s to 46s delays) | Automated script delivery (sub-second multi-stage payloads) | **Interactive Human Operator:** Keystroke timings indicate interactive manual terminal usage. |",
        "| **Payload & Post-Exploitation** | Benign discovery (`whoami`, `ls`, `pwd`) | Malware downloads (`wget`/`curl`), coinminers, persistence cron jobs | **Benign Reconnaissance:** No malicious binary drops or rootkits attempted. |",
        "| **Client Fingerprinting (HASSH)** | OpenSSH 9.6p1 (`aae6b9604f6f...`) | Custom scanning frameworks (Paramiko, libssh, Go-crypto, Masscan) | **Standard OS Client:** Originates from native Linux OpenSSH terminal client. |",
        "",
        "---",
        "",
        "## 6. MITRE ATT&CK Enterprise Matrix Mapping",
        "",
        "Each observed activity was cross-referenced against the MITRE ATT&CK Enterprise Matrix (v14+):",
        "",
        "| Tactic ID | Tactic Name | Technique ID | Technique Name | Observed Honeypot Evidence | Security Rationale |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
        "| **TA0001** | Initial Access | **T1078** | Valid Accounts | Login as `testuser` and `fakeuser` | Adversaries abuse credentials to gain authorized access to the target host. |",
        "| **TA0002** | Execution | **T1059.004** | Command and Scripting Interpreter: Unix Shell | PTY allocation (`linux`, 160x50), interactive bash session | Adversaries execute shell commands directly through Unix command interpreters. |",
        "| **TA0007** | Discovery | **T1033** | System Owner/User Discovery | Execution of `whoami` | Adversaries query current user identity to determine if they possess administrative/root privileges. |",
        "| **TA0007** | Discovery | **T1082** | System Information Discovery | Execution of `hostname` | Adversaries query machine hostname and system properties to map network architecture. |",
        "| **TA0007** | Discovery | **T1083** | File and Directory Discovery | Execution of `pwd` and `ls` | Adversaries enumerate directory contents and locate files of interest for exfiltration or abuse. |",
        "",
        "---",
        "",
        "## 7. ISO/IEC 27001:2022 Annex A Alignment",
        "",
        "> [!IMPORTANT]",
        "> **Academic Alignment Disclaimer:**  ",
        f"> {disclaimer['statement']}",
        "",
        "### Evaluated ISO/IEC 27001:2022 Controls",
        "",
    ]

    for c in iso_controls:
        report_lines.extend([
            f"### Control {c['control_id']}: {c['control_name']} ({c['theme']})",
            f"- **ISO Requirement Objective:** {c['iso_objective']}",
            f"- **Honeypot Monitoring Relevance:** {c['honeypot_relevance']}",
            f"- **Project Technical Evidence:** `{c['implementation_evidence']}`",
            f"- **Scope & Limitations:** *{c['boundary_caveat']}*",
            ""
        ])

    report_lines.extend([
        "---",
        "",
        "## 8. Honeypot Operational Risk Assessment",
        "",
        "Deploying deception technology in enterprise or academic environments introduces operational, legal, and architectural risks. The table below documents a formal qualitative 5x5 risk evaluation:",
        "",
        "| Risk ID | Threat Event & Vulnerability | Likelihood (1-5) | Impact (1-5) | Risk Score | Risk Level | Prescribed Mitigation Measure | Residual Risk |",
        "| :--- | :--- | :---: | :---: | :---: | :---: | :--- | :---: |",
    ])

    for r in risk_matrix:
        report_lines.append(
            f"| **{r['risk_id']}** | **{r['threat_event']}**<br>*{r['vulnerability']}* | {r['likelihood']} | {r['impact']} | {r['risk_score']} | **{r['risk_level']}** | {r['mitigation'].replace(chr(10), '<br>')} | {r['residual_risk']} |"
        )

    report_lines.extend([
        "",
        "---",
        "",
        "## 9. Limitations & Future Enhancements",
        "",
        "### Current Project Limitations",
        "1. **Controlled Localhost Dataset:** The current dataset consists of 2 localhost test sessions. While ideal for validating ingestion, parsing, sanitization, and visualization, it does not reflect high-volume automated Internet attacks.",
        "2. **Single Sensor Telemetry:** Telemetry is gathered from one standalone sensor instance without distributed multi-sensor correlation.",
        "3. **Absence of Malicious Binaries:** No file downloads (`wget`, `curl`) occurred in this test run; hence, malware sandbox detonation capabilities were not exercised.",
        "",
        "### Recommended Future Enhancements",
        "1. **Public DMZ / Cloud VPS Deployment:** Deploy Cowrie on an isolated public-facing server (e.g., AWS EC2, DigitalOcean, or university DMZ) with port 22 forwarded to capture real-world global threat actors.",
        "2. **Automated Threat Intelligence Enrichment:** Integrate IP geolocation APIs (MaxMind GeoIP2) and threat feeds (AbuseIPDB, VirusTotal, GreyNoise) to score connecting IPs automatically.",
        "3. **Centralized SIEM Ingestion:** Forward Cowrie JSON logs to an Elastic SIEM (ELK Stack) or Splunk cluster via Filebeat or syslog.",
        "4. **Automated Sandbox Detonation:** Integrate Cowrie's download hook with Cuckoo Sandbox or CAPEv2 to automatically detonate dropped ELF binaries.",
        "",
        "---",
        "",
        "## 10. Conclusion",
        "This project successfully developed and validated an end-to-end SSH honeypot monitoring and security analysis solution using Cowrie. By parsing, sanitizing, and analyzing actual honeypot logs, the system proved that:",
        "- Structured telemetry can be extracted without compromising data integrity or leaking sensitive credentials.",
        "- Human-paced simulated testing can be empirically distinguished from automated cyberattacks.",
        "- Deception telemetry maps directly to standardized cybersecurity frameworks (MITRE ATT&CK) and informs detective controls under ISO/IEC 27001:2022.",
        "- Honeypot deployment risks can be managed through strict isolation, egress filtering, and automated log sanitization.",
        "",
        "The project provides a comprehensive, defendable foundation for MCA Information Security Management Systems academic evaluation."
    ])

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines) + "\n")

    print(f"[+] Step 5 Complete: Academic Security Report written to {report_path}")
    return report_path


if __name__ == "__main__":
    generate_all()
