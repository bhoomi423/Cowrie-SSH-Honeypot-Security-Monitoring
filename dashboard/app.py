"""
Cowrie Honeypot Security Monitoring Dashboard Web Application.
MCA Information Security Management Systems Project.

Flask web application providing real-time visualization of honeypot telemetry,
threat analytics, MITRE ATT&CK mapping, and ISO 27001:2022 ISMS risk management.
Hardened with defense-in-depth security controls (CSP, sanitization, path validation).
"""

import os
import sys
import secrets
import tempfile
from pathlib import Path
from typing import Set

# Ensure Matplotlib uses a valid writable temporary config directory
os.environ["MPLCONFIGDIR"] = os.path.join(tempfile.gettempdir(), "matplotlib")

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, jsonify, render_template, send_from_directory, abort, Response, request
from werkzeug.utils import secure_filename
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

# Application Security Hardening: Cryptographic Secret Key
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB request limit
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 3600

# Allowed file extensions for evidence images
ALLOWED_IMAGE_EXTENSIONS: Set[str] = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"}


# Security Headers Middleware (OWASP Secure Headers Recommendation)
@app.after_request
def apply_security_headers(response: Response) -> Response:
    """Enforces defensive HTTP response headers across all views and API endpoints."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Server"] = "CowrieSOC/2.0"  # Mask underlying server fingerprints
    return response


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
    """Primary student lab implementation evidence screenshots."""
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


@app.route("/evidence-img/<path:filename>")
def evidence_img(filename: str):
    """
    Serves forensic evidence images with strict validation against path traversal.
    Ensures filenames are sanitized and restricted to whitelist extensions.
    """
    safe_name = secure_filename(filename)
    if not safe_name or safe_name != filename:
        abort(400, description="Invalid or malicious filename format.")

    ext = Path(safe_name).suffix.lower()
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        abort(403, description="Requested file extension is not permitted.")

    evidence_dir = (PROJECT_ROOT / "evidence").resolve()
    target_path = (evidence_dir / safe_name).resolve()

    # Guard against symlink or directory boundary escape
    if not str(target_path).startswith(str(evidence_dir)):
        abort(403, description="Access outside evidence directory denied.")

    if not target_path.exists() or not target_path.is_file():
        abort(404, description="Evidence image not found.")

    return send_from_directory(str(evidence_dir), safe_name)


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

    # Protect against DOM DoS: cap rendered records while reporting total count
    max_records = 100
    total_records = len(parser.sanitized_events)
    display_logs = parser.sanitized_events[:max_records]

    return render_template(
        "logs.html",
        active_page="logs",
        json_logs=display_logs,
        total_records=total_records,
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


# Defensive Error Handlers (Prevents stack trace / system information disclosure)
@app.errorhandler(400)
def handle_bad_request(e):
    return jsonify({"error": "Bad Request", "message": getattr(e, "description", "Malformed request.")}), 400


@app.errorhandler(403)
def handle_forbidden(e):
    return jsonify({"error": "Forbidden", "message": getattr(e, "description", "Access denied.")}), 403


@app.errorhandler(404)
def handle_not_found(e):
    return jsonify({"error": "Not Found", "message": getattr(e, "description", "Resource not found.")}), 404


@app.errorhandler(500)
def handle_server_error(e):
    return jsonify({"error": "Internal Server Error", "message": "An internal error occurred."}), 500


def run_server(host="127.0.0.1", port=5000, debug=False):
    """Starts the hardened Flask development server strictly on localhost."""
    print(f"[*] Starting Hardened Cowrie Honeypot SOC Dashboard on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_server()
