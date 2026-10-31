"""
Cowrie Honeypot Security Monitoring Dashboard Web Application.
MCA Information Security Management Systems Project.

Flask web application providing real-time visualization of honeypot telemetry,
threat analytics, MITRE ATT&CK mapping, and ISO 27001:2022 ISMS risk management.
"""

import os
import sys
import tempfile
from pathlib import Path

# Ensure Matplotlib uses a valid writable temporary config directory
os.environ["MPLCONFIGDIR"] = os.path.join(tempfile.gettempdir(), "matplotlib")

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, jsonify, render_template, send_from_directory
from src.parser import CowrieParser
from src.analyzer import ThreatAnalyzer
from src.visualizer import SecurityVisualizer
from src.mitre_mapper import MitreMapper
from src.iso27001_risk import ISO27001RiskManager

# Initialize Flask
app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "dashboard" / "templates"),
    static_folder=str(PROJECT_ROOT / "dashboard" / "static")
)

# Initialize Data & Pipelines
parser = CowrieParser(
    raw_json_path=str(PROJECT_ROOT / "cowrie.json"),
    raw_log_path=str(PROJECT_ROOT / "cowrie.log"),
    sanitized_dir=str(PROJECT_ROOT / "data")
)

# Run sanitization pipeline on startup
parser.sanitize_files()
parser.load_json_events()
parser.load_text_log_events()
sessions = parser.parse_sessions()
metrics = parser.get_summary_metrics()

analyzer = ThreatAnalyzer(sessions, metrics)
threat_info = analyzer.perform_threat_classification()
timelines = analyzer.build_session_timelines()
commands_data = analyzer.get_command_analysis()

# Generate charts
visualizer = SecurityVisualizer(output_dir=str(PROJECT_ROOT / "dashboard" / "static" / "images"))
mitre_events = [ev for s in sessions.values() for ev in MitreMapper.map_session_events(s)]
visualizer.generate_all_charts(metrics, commands_data, sessions, mitre_events)


@app.route("/")
def index():
    """Main executive overview dashboard."""
    return render_template(
        "index.html",
        active_page="index",
        metrics=metrics,
        sessions=sessions,
        threat_info=threat_info
    )


@app.route("/sessions")
def sessions_view():
    """Detailed SSH session reconstruction and event timelines."""
    return render_template(
        "sessions.html",
        active_page="sessions",
        timelines=timelines,
        metrics=metrics
    )


@app.route("/commands")
def commands_view():
    """Interactive command audit trail and typing cadence analysis."""
    return render_template(
        "commands.html",
        active_page="commands",
        commands_data=commands_data
    )


@app.route("/threat-analysis")
def threat_view():
    """Empirical threat classification and MITRE ATT&CK mapping."""
    return render_template(
        "threat_analysis.html",
        active_page="threat",
        threat_info=threat_info,
        metrics=metrics
    )


@app.route("/compliance-risk")
def compliance_view():
    """ISO/IEC 27001:2022 Annex A controls and ISMS Risk Assessment matrix."""
    return render_template(
        "compliance_risk.html",
        active_page="compliance",
        iso_controls=ISO27001RiskManager.get_iso_mappings(),
        risk_matrix=ISO27001RiskManager.get_risk_assessment_matrix(),
        disclaimer=ISO27001RiskManager.get_compliance_disclaimer()
    )


@app.route("/evidence")
def evidence_view():
    """Primary student lab implementation evidence (20 forensic screenshots)."""
    evidence_dir = PROJECT_ROOT / "evidence"
    evidence_files = []
    if evidence_dir.exists():
        for f in sorted(evidence_dir.glob("*.png")):
            evidence_files.append({
                "filename": f.name,
                "title": f.stem.replace("_", " ").title()
            })
    return render_template(
        "evidence.html",
        active_page="evidence",
        evidence_files=evidence_files
    )


@app.route("/evidence-img/<filename>")
def evidence_img(filename):
    """Serves forensic evidence images."""
    return send_from_directory(str(PROJECT_ROOT / "evidence"), filename)


@app.route("/logs")
def logs_view():
    """Sanitized raw event telemetry inspection."""
    sanitized_text_content = ""
    if parser.sanitized_log_path.exists():
        with open(parser.sanitized_log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            sanitized_text_content = "".join(lines[:60])  # Clean excerpt of first 60 lines
            if len(lines) > 60:
                sanitized_text_content += f"\n... [{len(lines) - 60} additional lines sanitized and logged] ..."

    return render_template(
        "logs.html",
        active_page="logs",
        json_logs=parser.sanitized_events,
        text_log_content=sanitized_text_content
    )


@app.route("/api/metrics")
def api_metrics():
    """REST API endpoint for summary metrics."""
    return jsonify(metrics)


@app.route("/api/sessions")
def api_sessions():
    """REST API endpoint for sanitized session data."""
    return jsonify(sessions)


def run_server(host="127.0.0.1", port=5000, debug=False):
    """Starts the Flask development server."""
    print(f"[*] Starting Cowrie Honeypot SOC Dashboard on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_server()
