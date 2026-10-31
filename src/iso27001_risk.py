"""
ISO 27001:2022 Mapping and Security Risk Assessment Module.
MCA Information Security Management Systems Project.

Provides:
1. Academic mapping to ISO/IEC 27001:2022 Annex A controls.
2. Objective analysis of how honeypots function as detective security controls.
3. Explicit disclaimers clarifying that this project demonstrates technical control
   implementation concepts and does not constitute organizational certification.
4. Structured Risk Assessment matrix covering honeypot deployment risks, likelihood,
   impact, risk level, and mitigation strategies.
"""

from typing import Any, Dict, List


class ISO27001RiskManager:
    """
    Manages ISO 27001:2022 Annex A control alignments and operational risk assessment.
    """

    @classmethod
    def get_iso_mappings(cls) -> List[Dict[str, Any]]:
        """
        Returns relevant ISO/IEC 27001:2022 controls and their technical correlation.
        """
        return [
            {
                "control_id": "A.8.15",
                "control_name": "Logging",
                "theme": "Technological controls",
                "iso_objective": "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.",
                "honeypot_relevance": "Cowrie generates granular, structured event telemetry (JSON and text logs) recording connection handshakes, authentication attempts, terminal dimensions, and verbatim command inputs. The project implements automated parsing, sanitization, and session tracking.",
                "implementation_evidence": "cowrie.json and cowrie.log parsing; password redaction in data/sanitized_cowrie.json; extraction of timestamps, IPs, and session metrics.",
                "boundary_caveat": "Academic demonstration only. Does not replace enterprise SIEM, centralized log retention policies, or cryptographic log non-repudiation required for organizational compliance."
            },
            {
                "control_id": "A.8.16",
                "control_name": "Monitoring activities",
                "theme": "Technological controls",
                "iso_objective": "Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.",
                "honeypot_relevance": "A honeypot serves as a specialized deception detection mechanism. Because a honeypot has no legitimate business usage, any interaction represents anomalous or unauthorized probing that warrants immediate security investigation.",
                "implementation_evidence": "Real-time parsing and SOC monitoring dashboard tracking SSH connections, command timelines, and authentication events.",
                "boundary_caveat": "Demonstrates detection and visualization techniques. Operational compliance requires continuous 24/7 SOC alerting and automated incident response workflows."
            },
            {
                "control_id": "A.8.20",
                "control_name": "Network security",
                "theme": "Technological controls",
                "iso_objective": "Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.",
                "honeypot_relevance": "Deploying Cowrie on an alternative port (2222) or inside an isolated network segment (DMZ/VLAN) diverts malicious reconnaissance away from production SSH (port 22) and protects underlying hosts.",
                "implementation_evidence": "Honeypot listening on port 2222; socket isolation preventing direct access to production Ubuntu services.",
                "boundary_caveat": "Testing was performed via loopback interface (127.0.0.1). Production network security requires firewall ACLs, egress filtering, and VLAN zoning."
            },
            {
                "control_id": "A.8.24",
                "control_name": "Use of cryptography",
                "theme": "Technological controls",
                "iso_objective": "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
                "honeypot_relevance": "Cowrie negotiates SSH key exchange algorithms, ciphers, and MACs, and calculates the client HASSH fingerprint (e.g. aae6b9604f6f3356543709a376d7f657) to audit client cryptographic capabilities.",
                "implementation_evidence": "Extraction and display of HASSH fingerprints, cipher suites, and key exchange algorithms in parser and dashboard.",
                "boundary_caveat": "Covers inspection of inbound cryptographic parameters; does not establish enterprise key management procedures."
            },
            {
                "control_id": "A.5.24",
                "control_name": "Information security incident management planning and preparation",
                "theme": "Organizational controls",
                "iso_objective": "The organization shall plan and prepare for managing information security incidents by defining, establishing and communicating incident management processes.",
                "honeypot_relevance": "Honeypot logs provide threat intelligence and early indicators of attack (IoAs), allowing incident response teams to prepare threat playbooks and understand attacker techniques before production assets are breached.",
                "implementation_evidence": "Threat analysis engine mapping captured behaviors to MITRE ATT&CK tactics (TA0001, TA0002, TA0007).",
                "boundary_caveat": "Supplies threat telemetry to inform incident planning; does not constitute an Incident Response Plan (IRP) or formal CSIRT charter."
            },
            {
                "control_id": "A.5.25",
                "control_name": "Assessment and decision on information security events",
                "theme": "Organizational controls",
                "iso_objective": "The organization shall assess information security events and decide if they are to be categorized as information security incidents.",
                "honeypot_relevance": "The analysis engine systematically evaluates incoming connections, distinguishing between benign internal verification testing (127.0.0.1) and malicious external attacks, preventing false alarms.",
                "implementation_evidence": "Threat categorization algorithm evaluating source IPs, command cadences, and authentication frequency.",
                "boundary_caveat": "Illustrates algorithmic event categorization; does not replace formal incident classification criteria defined by an ISMS steering committee."
            },
            {
                "control_id": "A.8.7",
                "control_name": "Protection against malware",
                "theme": "Technological controls",
                "iso_objective": "Protection against malware shall be implemented and supported by appropriate user awareness.",
                "honeypot_relevance": "Medium-interaction honeypots capture malware downloads, droppers, and curl/wget payloads into quarantined directories (var/lib/cowrie/downloads) for subsequent sandbox detonation.",
                "implementation_evidence": "Cowrie architecture includes automated download interception and SHA256 file hashing capabilities.",
                "boundary_caveat": "Captures payloads for analysis; does not replace host endpoint protection (EDR/AV) across the enterprise fleet."
            }
        ]

    @classmethod
    def get_risk_assessment_matrix(cls) -> List[Dict[str, Any]]:
        """
        Returns a comprehensive 5x5 qualitative risk assessment for honeypot operations.
        """
        return [
            {
                "risk_id": "RSK-01",
                "threat_event": "Honeypot Sandbox Escape & Host Compromise",
                "vulnerability": "Potential unpatched vulnerability in Twisted Python framework or Cowrie daemon allowing container/sandbox escape.",
                "likelihood": "Low (2)",
                "impact": "Very High (5)",
                "risk_score": 10,
                "risk_level": "Medium",
                "mitigation": "1. Run Cowrie under a non-root unprivileged service account ('cowrie').\n2. Deploy inside isolated Docker/LXC container or dedicated VM.\n3. Keep host OS (Ubuntu 24.04) and Python packages updated with latest security patches.\n4. Apply AppArmor / SELinux containment profiles.",
                "residual_risk": "Low"
            },
            {
                "risk_id": "RSK-02",
                "threat_event": "Honeypot Abused as Pivot / Lateral Movement Proxy",
                "vulnerability": "Unrestricted outbound network connectivity allowing an attacker who interacts with the honeypot to bounce traffic to other internal hosts.",
                "likelihood": "Low (2)",
                "impact": "High (4)",
                "risk_score": 8,
                "risk_level": "Medium",
                "mitigation": "1. Implement strict egress firewall rules (iptables/ufw) blocking all outbound RFC 1918 traffic.\n2. Disable SSH port forwarding in cowrie.cfg.\n3. Isolate the honeypot in a dedicated DMZ or guest network segment.",
                "residual_risk": "Low"
            },
            {
                "risk_id": "RSK-03",
                "threat_event": "Plaintext Credential Exposure in Logs & Dashboards",
                "vulnerability": "Cowrie records all entered passwords in plaintext; logs or dashboards could leak sensitive internal or test credentials.",
                "likelihood": "High (4)",
                "impact": "High (4)",
                "risk_score": 16,
                "risk_level": "High",
                "mitigation": "1. Automated data sanitization engine redacting passwords to '[REDACTED]' in data exports, UI, and reports.\n2. Restrict filesystem permissions on raw log files (chmod 600 cowrie.json).\n3. Enforce principle that honeypot passwords must never match legitimate corporate directory credentials.",
                "residual_risk": "Low (mitigated by project sanitization architecture)"
            },
            {
                "risk_id": "RSK-04",
                "threat_event": "Denial of Service & Disk Exhaustion via Log Flooding",
                "vulnerability": "High-volume automated brute-force attacks or large TTY session logs exhausting VM disk storage or CPU.",
                "likelihood": "Medium (3)",
                "impact": "Medium (3)",
                "risk_score": 9,
                "risk_level": "Medium",
                "mitigation": "1. Configure logrotate on cowrie.log and cowrie.json with strict file size caps.\n2. Limit concurrent SSH connections per IP in cowrie.cfg.\n3. Set dedicated disk partition quotas for /var/lib/cowrie.",
                "residual_risk": "Low"
            },
            {
                "risk_id": "RSK-05",
                "threat_event": "False Positive Alert Fatigue in Security Operations (SOC)",
                "vulnerability": "Internal authorized vulnerability scanning or testing triggering high-severity incident responses.",
                "likelihood": "High (4)",
                "impact": "Low (2)",
                "risk_score": 8,
                "risk_level": "Medium",
                "mitigation": "1. Programmatic classification engine that identifies loopback (127.0.0.1) and known test IP ranges.\n2. Tune SIEM alerting rules to differentiate between verification testing and unauthorized network probing.",
                "residual_risk": "Low"
            }
        ]

    @classmethod
    def get_compliance_disclaimer(cls) -> Dict[str, str]:
        """
        Explicit academic disclaimer for student viva and documentation.
        """
        return {
            "title": "ISO/IEC 27001:2022 Academic Alignment Disclaimer",
            "statement": (
                "This project demonstrates the technical implementation, logging capabilities, "
                "and threat monitoring principles referenced in ISO/IEC 27001:2022 Annex A controls "
                "(specifically A.8.15, A.8.16, A.8.20, A.8.24, A.5.24, A.5.25, and A.8.7). "
                "This implementation does NOT constitute, claim, or imply formal ISO 27001 "
                "certification, organizational compliance, or accreditation. Formal certification "
                "requires an independent third-party audit of the entire organizational Information "
                "Security Management System (ISMS), including executive governance, risk treatment plans, "
                "human resources policies, and continuous audit cycles."
            )
        }
