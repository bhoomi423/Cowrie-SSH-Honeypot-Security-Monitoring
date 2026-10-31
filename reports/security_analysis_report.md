# SSH Honeypot Monitoring and Security Analysis Using Cowrie
## Practical Cybersecurity Project Report
**Degree Program:** Master of Computer Applications (MCA)  
**Specialization:** Information Security Management Systems (ISMS)  
**Target Environment:** VMware Workstation Pro 17 | Ubuntu Server 24.04.5 LTS | Cowrie SSH Honeypot | Python 3  
**Sensor UUID:** `b87bf595-d41c-11f1-83af-000c296f4a56` | **Sensor Mode:** SSH on Port 2222  
**Data Confidentiality Notice:** All sensitive passwords have been sanitized and redacted (`[REDACTED]`). Original raw logs preserved intact.

---

## 1. Executive Summary
This project establishes a security monitoring, threat intelligence, and compliance assessment solution based on telemetry captured by a Cowrie SSH Honeypot. Cowrie was deployed on an Ubuntu Server 24.04 virtual machine within VMware Workstation Pro 17 to emulate a high-value UNIX SSH server and intercept unauthorized access attempts.

During the operational monitoring window, two distinct SSH interaction sessions were captured. Detailed analysis reveals that both sessions originated from the local loopback interface (`127.0.0.1`), demonstrating controlled internal verification and smoke-testing rather than external threat actor incursions. All authentication attempts succeeded due to Cowrie's default credential ingestion policy. The first session contained interactive reconnaissance commands (`whoami`, `hostname`, `pwd`, `ls`, `exit`), while the second session terminated immediately after authentication.

A modular Python security architecture was developed to parse raw JSON and Twisted logs, calculate session state metrics, map adversary tactics to the MITRE ATT&CK framework, align technical detective capabilities with ISO/IEC 27001:2022 Annex A controls, and perform a formal ISMS 5x5 qualitative risk assessment.

### Key Quantitative Metrics
- **Total Ingested Log Events:** 25
- **Total Monitored Sessions:** 2
- **Unique Source IP Addresses:** 1 (`127.0.0.1` - Loopback Interface)
- **Total Authentication Attempts:** 2
- **Successful Authentication Events:** 2 (100% success rate under Cowrie evaluation mode)
- **Failed Authentication Events:** 0
- **Total Executed Shell Commands:** 7 (5 unique: `exit`, `hostname`, `ls`, `pwd`, `whoami`)
- **Total Engagement Duration:** 372.95 seconds (~6 minutes 13 seconds)
- **Average Session Duration:** 186.47 seconds

---

## 2. Architecture & Operational Workflow
The project architecture separates detection, ingestion, parsing, sanitization, analysis, and presentation into decoupled layers:

```
+-------------------------------------------------------------------------+
|                     DECEPTION SENSOR LAYER                             |
|  Ubuntu Server 24.04 (VMware Pro 17) -> Cowrie SSH Honeypot (Port 2222) |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                       RAW TELEMETRY STORAGE                             |
|  - cowrie.json (Structured JSON-L)   - cowrie.log (Twisted Text Logs)   |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                   PARSING & SANITIZATION LAYER                          |
|  - CowrieParser (src/parser.py)                                         |
|  - Preserves originals; generates data/sanitized_cowrie.*               |
|  - Redacts plaintext passwords to [REDACTED] in memory and storage      |
+-------------------------------------------------------------------------+
                                     |
                  +------------------+------------------+
                  |                                     |
                  v                                     v
+------------------------------------+ +----------------------------------+
|     THREAT & BEHAVIORAL ANALYZER   | |    COMPLIANCE & RISK ENGINE      |
| - ThreatAnalyzer (src/analyzer.py) | | - ISO27001RiskManager            |
| - Session timeline construction    | |   (src/iso27001_risk.py)         |
| - MITRE ATT&CK correlation         | | - ISO 27001:2022 Annex A Mapping |
| - Localhost vs external heuristics | | - 5x5 ISMS Risk Assessment       |
+------------------------------------+ +----------------------------------+
                  |                                     |
                  +------------------+------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                      VISUALIZATION & SOC DASHBOARD                      |
|  - SecurityVisualizer (src/visualizer.py) -> High-Res Themed Charts     |
|  - Flask SOC Dashboard (dashboard/app.py) -> Multi-view Web Console     |
+-------------------------------------------------------------------------+
```

---

## 3. Student Implementation Evidence & Lab Milestones

The student conducted end-to-end practical deployment and verification in the VMware Workstation Pro 17 virtualized lab environment. Seven primary forensic evidence milestones were captured and archived in `evidence/` to corroborate each milestone:

### Milestone 1: Host Environment & Network Setup (`evidence/01_vm_environment_and_ip.png`)
Ubuntu Server 24.04.5 LTS guest OS splash screen running in VMware Workstation Pro 17, confirming IPv4 address `192.168.28.131` on virtual network adapter `ens33`.

### Milestone 2: Cowrie Honeypot Authentication Configuration (`evidence/02_cowrie_auth_configuration.png`)
Terminal inspection of `etc/cowrie.cfg` verifying `auth_class = UserDB` and demonstrating interactive exit from the honeypot's emulated shell.

### Milestone 3: Authentication Fallback & Wildcard Rule (`evidence/03_userdb_wildcard_fallback.png`)
Investigation of Cowrie's `userdb.example` showing the terminal wildcard rule `*:x:*`. When `userdb.txt` is absent, Cowrie's authentication engine (`src/cowrie/core/auth.py`) activates this default, explaining why `testuser` and `fakeuser` were accepted.

### Milestone 4: Raw In-VM Telemetry Logs (`evidence/04_raw_log_files_in_vm.png`)
Directory listing of `/home/cowrie/cowrie/var/log/cowrie/` inside Ubuntu confirming the existence, sizes, and timestamps of `cowrie.json` (13 KB) and `cowrie.log` (8.8 KB).

### Milestone 5: In-VM Session Duration Calculation (`evidence/05_in_vm_session_duration.png`)
Inline Python script running inside the Ubuntu VM calculating Session 1 duration as `0:03:24.442211` (~204.44 seconds) and verifying the `testuser` login event, matching our analytical parser exactly.

### Milestone 6: In-VM Command Sequence Audit (`evidence/06_in_vm_command_audit.png`)
Inline Python command parser output verifying the exact execution sequence and timestamps: `whoami`, `hostname`, `pwd`, `ls`, `ls`, and `exit`.

### Milestone 7: Cross-Platform Forensic SCP Transfer (`evidence/07_scp_export_to_windows.png`)
Windows PowerShell terminal session demonstrating folder creation and 100% transfer completion of `cowrie.json` (12 KB) and `cowrie.log` (8,922 bytes) from `labuser@192.168.28.131:/tmp/` into the Windows analysis workspace.

---

## 4. Session & Behavioral Telemetry Analysis

### Session 1: `980210c2cbb3` (Interactive Reconnaissance)
- **Connection Time:** `2026-10-30T04:54:00.138369Z`
- **Disconnection Time:** `2026-10-30T04:57:24.580580Z`
- **Duration:** `204.44` seconds (~3 minutes 24 seconds)
- **Source Endpoint:** `127.0.0.1:41440` -> `127.0.0.1:2222`
- **Client Banner:** `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`
- **HASSH Fingerprint:** `aae6b9604f6f3356543709a376d7f657`
- **Authenticated Identity:** `testuser` (Password: `[REDACTED]`)
- **TTY Session Recording:** `var/lib/cowrie/tty/51b3d31ad1b7b3afcc6194f05ef575b82686aa82f43722ca5d0bc03d07685011`
- **Observed Command Sequence:**
  1. `whoami` (`04:55:21Z`) - Querying active user permissions.
  2. `hostname` (`04:55:39Z`) - Enumerating host system identifier.
  3. `pwd` (`04:56:05Z`) - Determining current directory location.
  4. `ls` (`04:56:28Z`) - Listing home directory files.
  5. `ls` (`04:56:38Z`) - Re-verifying directory listing.
  6. `exit` (`04:57:24Z`) - Cleanly logging out.

### Session 2: `87e196a90797` (Authentication Smoke-Test)
- **Connection Time:** `2026-10-30T14:57:02.626910Z`
- **Disconnection Time:** `2026-10-30T14:59:51.147867Z`
- **Duration:** `168.51` seconds (~2 minutes 48 seconds)
- **Source Endpoint:** `127.0.0.1:57560` -> `127.0.0.1:2222`
- **Client Banner:** `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`
- **HASSH Fingerprint:** `aae6b9604f6f3356543709a376d7f657`
- **Authenticated Identity:** `fakeuser` (Password: `[REDACTED]`)
- **TTY Session Recording:** `var/lib/cowrie/tty/076d0f83ea5ae0f758a8088a9dfe2b2510c4b78a283f0ad8bcafbff6a7e412fb`
- **Observed Command Sequence:**
  1. `exit ` (`14:59:51Z`) - Immediate terminal exit without issuing exploration commands.

---

## 5. Threat Analysis: Simulated Testing vs. Genuine External Attacks

A critical requirement in security intelligence is ensuring that monitoring systems do not falsely mischaracterize benign administrative validation as external threat actor activity.

| Evaluation Dimension | Observed Project Telemetry | Real-World External Attack Baseline | Analyst Conclusion |
| :--- | :--- | :--- | :--- |
| **Source IP & Routing** | `127.0.0.1` (Local Loopback) | Publicly routable IPs (Tor nodes, bulletproof hosters, residential proxies) | **Controlled Local Test:** Packets never traversed external internet gateways. |
| **Authentication Frequency** | Exactly 2 logins across a 10-hour span | Automated credential stuffing: hundreds of attempts per second | **Manual Verification:** Human login pacing without brute-force dictionaries. |
| **Authentication Outcome** | 100% Success (2/2) | Low success rates (<0.1%) against hardened targets | **Honeypot Acceptance:** Validates Cowrie's default configuration accepting test credentials. |
| **Command Execution Pacing** | Human typing intervals (18s to 46s delays) | Automated script delivery (sub-second multi-stage payloads) | **Interactive Human Operator:** Keystroke timings indicate interactive manual terminal usage. |
| **Payload & Post-Exploitation** | Benign discovery (`whoami`, `ls`, `pwd`) | Malware downloads (`wget`/`curl`), coinminers, persistence cron jobs | **Benign Reconnaissance:** No malicious binary drops or rootkits attempted. |
| **Client Fingerprinting (HASSH)** | OpenSSH 9.6p1 (`aae6b9604f6f...`) | Custom scanning frameworks (Paramiko, libssh, Go-crypto, Masscan) | **Standard OS Client:** Originates from native Linux OpenSSH terminal client. |

---

## 6. MITRE ATT&CK Enterprise Matrix Mapping

Each observed activity was cross-referenced against the MITRE ATT&CK Enterprise Matrix (v14+):

| Tactic ID | Tactic Name | Technique ID | Technique Name | Observed Honeypot Evidence | Security Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TA0001** | Initial Access | **T1078** | Valid Accounts | Login as `testuser` and `fakeuser` | Adversaries abuse credentials to gain authorized access to the target host. |
| **TA0002** | Execution | **T1059.004** | Command and Scripting Interpreter: Unix Shell | PTY allocation (`linux`, 160x50), interactive bash session | Adversaries execute shell commands directly through Unix command interpreters. |
| **TA0007** | Discovery | **T1033** | System Owner/User Discovery | Execution of `whoami` | Adversaries query current user identity to determine if they possess administrative/root privileges. |
| **TA0007** | Discovery | **T1082** | System Information Discovery | Execution of `hostname` | Adversaries query machine hostname and system properties to map network architecture. |
| **TA0007** | Discovery | **T1083** | File and Directory Discovery | Execution of `pwd` and `ls` | Adversaries enumerate directory contents and locate files of interest for exfiltration or abuse. |

---

## 7. ISO/IEC 27001:2022 Annex A Alignment

> [!IMPORTANT]
> **Academic Alignment Disclaimer:**  
> This project demonstrates the technical implementation, logging capabilities, and threat monitoring principles referenced in ISO/IEC 27001:2022 Annex A controls (specifically A.8.15, A.8.16, A.8.20, A.8.24, A.5.24, A.5.25, and A.8.7). This implementation does NOT constitute, claim, or imply formal ISO 27001 certification, organizational compliance, or accreditation. Formal certification requires an independent third-party audit of the entire organizational Information Security Management System (ISMS), including executive governance, risk treatment plans, human resources policies, and continuous audit cycles.

### Evaluated ISO/IEC 27001:2022 Controls

### Control A.8.15: Logging (Technological controls)
- **ISO Requirement Objective:** Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.
- **Honeypot Monitoring Relevance:** Cowrie generates granular, structured event telemetry (JSON and text logs) recording connection handshakes, authentication attempts, terminal dimensions, and verbatim command inputs. The project implements automated parsing, sanitization, and session tracking.
- **Project Technical Evidence:** `cowrie.json and cowrie.log parsing; password redaction in data/sanitized_cowrie.json; extraction of timestamps, IPs, and session metrics.`
- **Scope & Limitations:** *Academic demonstration only. Does not replace enterprise SIEM, centralized log retention policies, or cryptographic log non-repudiation required for organizational compliance.*

### Control A.8.16: Monitoring activities (Technological controls)
- **ISO Requirement Objective:** Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.
- **Honeypot Monitoring Relevance:** A honeypot serves as a specialized deception detection mechanism. Because a honeypot has no legitimate business usage, any interaction represents anomalous or unauthorized probing that warrants immediate security investigation.
- **Project Technical Evidence:** `Real-time parsing and SOC monitoring dashboard tracking SSH connections, command timelines, and authentication events.`
- **Scope & Limitations:** *Demonstrates detection and visualization techniques. Operational compliance requires continuous 24/7 SOC alerting and automated incident response workflows.*

### Control A.8.20: Network security (Technological controls)
- **ISO Requirement Objective:** Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.
- **Honeypot Monitoring Relevance:** Deploying Cowrie on an alternative port (2222) or inside an isolated network segment (DMZ/VLAN) diverts malicious reconnaissance away from production SSH (port 22) and protects underlying hosts.
- **Project Technical Evidence:** `Honeypot listening on port 2222; socket isolation preventing direct access to production Ubuntu services.`
- **Scope & Limitations:** *Testing was performed via loopback interface (127.0.0.1). Production network security requires firewall ACLs, egress filtering, and VLAN zoning.*

### Control A.8.24: Use of cryptography (Technological controls)
- **ISO Requirement Objective:** Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.
- **Honeypot Monitoring Relevance:** Cowrie negotiates SSH key exchange algorithms, ciphers, and MACs, and calculates the client HASSH fingerprint (e.g. aae6b9604f6f3356543709a376d7f657) to audit client cryptographic capabilities.
- **Project Technical Evidence:** `Extraction and display of HASSH fingerprints, cipher suites, and key exchange algorithms in parser and dashboard.`
- **Scope & Limitations:** *Covers inspection of inbound cryptographic parameters; does not establish enterprise key management procedures.*

### Control A.5.24: Information security incident management planning and preparation (Organizational controls)
- **ISO Requirement Objective:** The organization shall plan and prepare for managing information security incidents by defining, establishing and communicating incident management processes.
- **Honeypot Monitoring Relevance:** Honeypot logs provide threat intelligence and early indicators of attack (IoAs), allowing incident response teams to prepare threat playbooks and understand attacker techniques before production assets are breached.
- **Project Technical Evidence:** `Threat analysis engine mapping captured behaviors to MITRE ATT&CK tactics (TA0001, TA0002, TA0007).`
- **Scope & Limitations:** *Supplies threat telemetry to inform incident planning; does not constitute an Incident Response Plan (IRP) or formal CSIRT charter.*

### Control A.5.25: Assessment and decision on information security events (Organizational controls)
- **ISO Requirement Objective:** The organization shall assess information security events and decide if they are to be categorized as information security incidents.
- **Honeypot Monitoring Relevance:** The analysis engine systematically evaluates incoming connections, distinguishing between benign internal verification testing (127.0.0.1) and malicious external attacks, preventing false alarms.
- **Project Technical Evidence:** `Threat categorization algorithm evaluating source IPs, command cadences, and authentication frequency.`
- **Scope & Limitations:** *Illustrates algorithmic event categorization; does not replace formal incident classification criteria defined by an ISMS steering committee.*

### Control A.8.7: Protection against malware (Technological controls)
- **ISO Requirement Objective:** Protection against malware shall be implemented and supported by appropriate user awareness.
- **Honeypot Monitoring Relevance:** Medium-interaction honeypots capture malware downloads, droppers, and curl/wget payloads into quarantined directories (var/lib/cowrie/downloads) for subsequent sandbox detonation.
- **Project Technical Evidence:** `Cowrie architecture includes automated download interception and SHA256 file hashing capabilities.`
- **Scope & Limitations:** *Captures payloads for analysis; does not replace host endpoint protection (EDR/AV) across the enterprise fleet.*

---

## 8. Honeypot Operational Risk Assessment

Deploying deception technology in enterprise or academic environments introduces operational, legal, and architectural risks. The table below documents a formal qualitative 5x5 risk evaluation:

| Risk ID | Threat Event & Vulnerability | Likelihood (1-5) | Impact (1-5) | Risk Score | Risk Level | Prescribed Mitigation Measure | Residual Risk |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- | :---: |
| **RSK-01** | **Honeypot Sandbox Escape & Host Compromise**<br>*Potential unpatched vulnerability in Twisted Python framework or Cowrie daemon allowing container/sandbox escape.* | Low (2) | Very High (5) | 10 | **Medium** | 1. Run Cowrie under a non-root unprivileged service account ('cowrie').<br>2. Deploy inside isolated Docker/LXC container or dedicated VM.<br>3. Keep host OS (Ubuntu 24.04) and Python packages updated with latest security patches.<br>4. Apply AppArmor / SELinux containment profiles. | Low |
| **RSK-02** | **Honeypot Abused as Pivot / Lateral Movement Proxy**<br>*Unrestricted outbound network connectivity allowing an attacker who interacts with the honeypot to bounce traffic to other internal hosts.* | Low (2) | High (4) | 8 | **Medium** | 1. Implement strict egress firewall rules (iptables/ufw) blocking all outbound RFC 1918 traffic.<br>2. Disable SSH port forwarding in cowrie.cfg.<br>3. Isolate the honeypot in a dedicated DMZ or guest network segment. | Low |
| **RSK-03** | **Plaintext Credential Exposure in Logs & Dashboards**<br>*Cowrie records all entered passwords in plaintext; logs or dashboards could leak sensitive internal or test credentials.* | High (4) | High (4) | 16 | **High** | 1. Automated data sanitization engine redacting passwords to '[REDACTED]' in data exports, UI, and reports.<br>2. Restrict filesystem permissions on raw log files (chmod 600 cowrie.json).<br>3. Enforce principle that honeypot passwords must never match legitimate corporate directory credentials. | Low (mitigated by project sanitization architecture) |
| **RSK-04** | **Denial of Service & Disk Exhaustion via Log Flooding**<br>*High-volume automated brute-force attacks or large TTY session logs exhausting VM disk storage or CPU.* | Medium (3) | Medium (3) | 9 | **Medium** | 1. Configure logrotate on cowrie.log and cowrie.json with strict file size caps.<br>2. Limit concurrent SSH connections per IP in cowrie.cfg.<br>3. Set dedicated disk partition quotas for /var/lib/cowrie. | Low |
| **RSK-05** | **False Positive Alert Fatigue in Security Operations (SOC)**<br>*Internal authorized vulnerability scanning or testing triggering high-severity incident responses.* | High (4) | Low (2) | 8 | **Medium** | 1. Programmatic classification engine that identifies loopback (127.0.0.1) and known test IP ranges.<br>2. Tune SIEM alerting rules to differentiate between verification testing and unauthorized network probing. | Low |

---

## 9. Limitations & Future Enhancements

### Current Project Limitations
1. **Controlled Localhost Dataset:** The current dataset consists of 2 localhost test sessions. While ideal for validating ingestion, parsing, sanitization, and visualization, it does not reflect high-volume automated Internet attacks.
2. **Single Sensor Telemetry:** Telemetry is gathered from one standalone sensor instance without distributed multi-sensor correlation.
3. **Absence of Malicious Binaries:** No file downloads (`wget`, `curl`) occurred in this test run; hence, malware sandbox detonation capabilities were not exercised.

### Recommended Future Enhancements
1. **Public DMZ / Cloud VPS Deployment:** Deploy Cowrie on an isolated public-facing server (e.g., AWS EC2, DigitalOcean, or university DMZ) with port 22 forwarded to capture real-world global threat actors.
2. **Automated Threat Intelligence Enrichment:** Integrate IP geolocation APIs (MaxMind GeoIP2) and threat feeds (AbuseIPDB, VirusTotal, GreyNoise) to score connecting IPs automatically.
3. **Centralized SIEM Ingestion:** Forward Cowrie JSON logs to an Elastic SIEM (ELK Stack) or Splunk cluster via Filebeat or syslog.
4. **Automated Sandbox Detonation:** Integrate Cowrie's download hook with Cuckoo Sandbox or CAPEv2 to automatically detonate dropped ELF binaries.

---

## 10. Conclusion
This project successfully developed and validated an end-to-end SSH honeypot monitoring and security analysis solution using Cowrie. By parsing, sanitizing, and analyzing actual honeypot logs, the system proved that:
- Structured telemetry can be extracted without compromising data integrity or leaking sensitive credentials.
- Human-paced simulated testing can be empirically distinguished from automated cyberattacks.
- Deception telemetry maps directly to standardized cybersecurity frameworks (MITRE ATT&CK) and informs detective controls under ISO/IEC 27001:2022.
- Honeypot deployment risks can be managed through strict isolation, egress filtering, and automated log sanitization.

The project provides a comprehensive, defendable foundation for MCA Information Security Management Systems academic evaluation.
