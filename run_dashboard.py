"""
Cowrie Honeypot Security Monitoring Dashboard Launcher.
MCA Information Security Management Systems Project.

Usage:
    python run_dashboard.py
    (Then open http://127.0.0.1:5000 in your browser)
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.app import run_server

if __name__ == "__main__":
    print("=" * 72)
    print("  COWRIE SSH HONEYPOT SECURITY MONITORING & ANALYSIS SYSTEM")
    print("  MCA Information Security Management Systems (ISMS) Practical Project")
    print("=" * 72)
    print("  Status: All raw logs preserved. Sensitive credentials sanitized.")
    print("  Dashboard UI: http://127.0.0.1:5000")
    print("  Press Ctrl+C to terminate the dashboard server.")
    print("=" * 72)
    try:
        run_server(host="127.0.0.1", port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n[*] Dashboard server stopped cleanly.")
