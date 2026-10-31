"""
Automated Test & Screenshot Capture Utility.
MCA Information Security Management Systems Project.

Starts Flask dashboard locally, validates HTTP endpoints,
and captures pixel-perfect high-resolution screenshots using headless Edge/Chrome.
"""

import os
import subprocess
import sys
import time
from pathlib import Path
import urllib.request

PROJECT_ROOT = Path(__file__).resolve().parent
SCREENSHOTS_DIR = PROJECT_ROOT / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

# Locate browser binary (Edge or Chrome)
EDGE_PATH = Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe")
CHROME_PATH = Path("C:/Program Files/Google/Chrome/Application/chrome.exe")

BROWSER_EXE = None
if EDGE_PATH.exists():
    BROWSER_EXE = str(EDGE_PATH)
elif CHROME_PATH.exists():
    BROWSER_EXE = str(CHROME_PATH)
else:
    print("[-] Warning: Neither Edge nor Chrome found at standard paths.")


def capture_all():
    print("[*] Launching Flask Server for Test Verification on port 5005...")
    env = os.environ.copy()
    env["FLASK_RUN_PORT"] = "5005"
    
    server_process = subprocess.Popen(
        [sys.executable, "-c", "from dashboard.app import app; app.run(host='127.0.0.1', port=5005)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(PROJECT_ROOT)
    )

    base_url = "http://127.0.0.1:5005"
    server_ready = False

    # Poll server readiness
    for i in range(15):
        time.sleep(1)
        try:
            with urllib.request.urlopen(f"{base_url}/api/metrics", timeout=2) as response:
                if response.status == 200:
                    server_ready = True
                    print("[+] Flask server is active and responding!")
                    break
        except Exception:
            pass

    if not server_ready:
        print("[-] Error: Flask server failed to respond within 15 seconds.")
        server_process.terminate()
        return False

    pages = [
        ("/", "01_overview_dashboard.png", "Overview Dashboard"),
        ("/sessions", "02_session_timelines.png", "Session Timelines"),
        ("/commands", "03_command_audit.png", "Command Audit Trail"),
        ("/threat-analysis", "04_threat_analysis_mitre.png", "Threat & MITRE ATT&CK"),
        ("/compliance-risk", "05_iso27001_risk_matrix.png", "ISO 27001 & Risk Matrix"),
        ("/evidence", "07_lab_evidence.png", "Lab Implementation Evidence"),
        ("/logs", "06_sanitized_logs.png", "Sanitized Logs Viewer")
    ]

    all_passed = True

    try:
        for path, filename, title in pages:
            url = f"{base_url}{path}"
            output_file = SCREENSHOTS_DIR / filename

            # 1. Verify HTTP Response
            try:
                req = urllib.request.urlopen(url, timeout=5)
                status = req.status
                print(f"[+] Tested {path} -> HTTP {status} (OK)")
            except Exception as e:
                print(f"[-] Endpoint test failed for {path}: {e}")
                all_passed = False
                continue

            # 2. Capture Headless Screenshot
            if BROWSER_EXE:
                cmd = [
                    BROWSER_EXE,
                    "--headless",
                    "--disable-gpu",
                    "--hide-scrollbars",
                    "--window-size=1360,950",
                    f"--screenshot={str(output_file)}",
                    url
                ]
                res = subprocess.run(cmd, capture_output=True, timeout=30)
                if output_file.exists() and output_file.stat().st_size > 0:
                    print(f"    -> Screenshot captured: {filename} ({output_file.stat().st_size} bytes)")
                else:
                    print(f"    [-] Failed to capture screenshot for {path}")
                    all_passed = False

    finally:
        print("[*] Stopping background test server...")
        server_process.terminate()
        server_process.wait(timeout=5)

    return all_passed


if __name__ == "__main__":
    success = capture_all()
    sys.exit(0 if success else 1)
