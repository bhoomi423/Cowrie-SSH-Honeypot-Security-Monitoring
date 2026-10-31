"""
Security Visualization & Chart Generator Module.
MCA Information Security Management Systems Project.

Generates publication-quality charts and visualizations for:
1. Event Type Distribution
2. Command Execution Frequency
3. Session Duration Comparison
4. MITRE ATT&CK Tactic Mapping Breakdown
5. ISO 27001 / ISMS 5x5 Risk Matrix Heatmap
"""

from pathlib import Path
from typing import Any, Dict, List
import matplotlib
matplotlib.use("Agg")  # Headless backend
import matplotlib.pyplot as plt
import numpy as np


class SecurityVisualizer:
    """
    Renders high-resolution security analytics charts using Matplotlib.
    Applies dark SOC-inspired styling for professional dashboard integration.
    """

    def __init__(self, output_dir: str = "dashboard/static/images"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Dark theme styling configuration
        self.bg_color = "#0f172a"        # Dark slate background
        self.card_bg = "#1e293b"         # Card background
        self.text_color = "#f8fafc"      # Pure light text
        self.grid_color = "#334155"      # Subtle slate grid
        self.accent_blue = "#38bdf8"     # Sky blue
        self.accent_green = "#34d399"    # Emerald
        self.accent_amber = "#fbbf24"    # Amber
        self.accent_rose = "#f43f5e"     # Rose / Red
        self.accent_purple = "#a78bfa"   # Violet

    def _apply_theme(self, fig, ax):
        """Applies dark security operations center theme to figure and axis."""
        fig.patch.set_facecolor(self.card_bg)
        ax.set_facecolor(self.bg_color)
        ax.tick_params(colors=self.text_color, labelsize=10)
        ax.xaxis.label.set_color(self.text_color)
        ax.yaxis.label.set_color(self.text_color)
        ax.title.set_color(self.text_color)
        for spine in ax.spines.values():
            spine.set_color(self.grid_color)
        ax.grid(color=self.grid_color, linestyle="--", linewidth=0.6, alpha=0.7)

    def generate_all_charts(
        self,
        summary_metrics: Dict[str, Any],
        command_analysis: Dict[str, Any],
        sessions: Dict[str, Dict[str, Any]],
        mitre_events: List[Dict[str, Any]]
    ) -> Dict[str, str]:
        """
        Generates the full suite of security charts and returns paths.
        """
        paths = {}
        paths["event_distribution"] = self.plot_event_distribution(summary_metrics.get("event_type_distribution", {}))
        paths["command_frequency"] = self.plot_command_frequency(command_analysis.get("command_occurrences", {}))
        paths["session_durations"] = self.plot_session_durations(sessions)
        paths["mitre_tactics"] = self.plot_mitre_tactics(mitre_events)
        paths["risk_matrix"] = self.plot_risk_matrix()
        return paths

    def plot_event_distribution(self, event_dist: Dict[str, int]) -> str:
        """Bar chart of Cowrie event types."""
        fig, ax = plt.subplots(figsize=(8.5, 4.8), dpi=150)
        self._apply_theme(fig, ax)

        # Simplify event names for clean display
        labels = [k.replace("cowrie.", "") for k in event_dist.keys()]
        values = list(event_dist.values())

        bars = ax.barh(labels, values, color=self.accent_blue, edgecolor="#0284c7", height=0.65)
        ax.bar_label(bars, padding=4, color=self.text_color, fontweight="bold", fontsize=9)

        ax.set_title("Cowrie Honeypot Event Type Distribution (Total: 25 Events)", fontsize=12, pad=12, fontweight="bold")
        ax.set_xlabel("Event Count", fontsize=10, labelpad=8)
        ax.invert_yaxis()
        fig.tight_layout()

        output_path = self.output_dir / "event_distribution.png"
        fig.savefig(output_path, facecolor=fig.get_facecolor(), bbox_inches="tight")
        plt.close(fig)
        return str(output_path)

    def plot_command_frequency(self, command_counts: Dict[str, int]) -> str:
        """Horizontal bar chart showing executed commands."""
        fig, ax = plt.subplots(figsize=(7.5, 4.2), dpi=150)
        self._apply_theme(fig, ax)

        # Sort commands by frequency
        sorted_cmds = sorted(command_counts.items(), key=lambda x: x[1], reverse=True)
        commands = [f"`{c[0]}`" for c in sorted_cmds]
        counts = [c[1] for c in sorted_cmds]

        colors = [self.accent_amber if c in ["`ls`", "`exit`"] else self.accent_green for c in commands]
        bars = ax.bar(commands, counts, color=colors, edgecolor="#0f172a", width=0.55)
        ax.bar_label(bars, padding=3, color=self.text_color, fontweight="bold", fontsize=10)

        ax.set_title("Observed Session Command Frequency (Total: 7 Commands)", fontsize=12, pad=12, fontweight="bold")
        ax.set_ylabel("Execution Count", fontsize=10)
        ax.set_ylim(0, max(counts) + 1.2)
        fig.tight_layout()

        output_path = self.output_dir / "command_frequency.png"
        fig.savefig(output_path, facecolor=fig.get_facecolor(), bbox_inches="tight")
        plt.close(fig)
        return str(output_path)

    def plot_session_durations(self, sessions: Dict[str, Dict[str, Any]]) -> str:
        """Session duration comparison."""
        fig, ax = plt.subplots(figsize=(7.5, 4.2), dpi=150)
        self._apply_theme(fig, ax)

        session_labels = []
        durations = []
        users = []

        for sid, s in sessions.items():
            user = s.get("successful_logins", [{}])[0].get("username", "unknown")
            session_labels.append(f"Session {sid[:8]}...\n(User: {user})")
            durations.append(s.get("duration_seconds", 0.0))
            users.append(user)

        bars = ax.bar(session_labels, durations, color=[self.accent_purple, self.accent_blue], width=0.45)
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f"{height:.1f}s\n(~{int(height//60)}m {int(height%60)}s)",
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 4), textcoords="offset points",
                        ha='center', va='bottom', color=self.text_color,
                        fontweight="bold", fontsize=9)

        ax.set_title("SSH Session Engagement Durations (Total: 372.95s / 6m 13s)", fontsize=12, pad=14, fontweight="bold")
        ax.set_ylabel("Duration (Seconds)", fontsize=10)
        ax.set_ylim(0, max(durations) + 60)
        fig.tight_layout()

        output_path = self.output_dir / "session_durations.png"
        fig.savefig(output_path, facecolor=fig.get_facecolor(), bbox_inches="tight")
        plt.close(fig)
        return str(output_path)

    def plot_mitre_tactics(self, mitre_events: List[Dict[str, Any]]) -> str:
        """Donut chart of observed MITRE ATT&CK tactics."""
        fig, ax = plt.subplots(figsize=(6.8, 4.2), dpi=150)
        fig.patch.set_facecolor(self.card_bg)

        # Tally tactics
        tactic_counts = {}
        for ev in mitre_events:
            tac = ev.get("tactic", "Uncategorized")
            tactic_counts[tac] = tactic_counts.get(tac, 0) + 1

        labels = list(tactic_counts.keys())
        values = list(tactic_counts.values())
        colors = [self.accent_blue, self.accent_purple, self.accent_amber, self.accent_green][:len(labels)]

        wedges, texts, autotexts = ax.pie(
            values,
            labels=labels,
            autopct="%1.0f%%",
            pctdistance=0.75,
            colors=colors,
            wedgeprops=dict(width=0.4, edgecolor=self.bg_color, linewidth=2),
            textprops=dict(color=self.text_color, fontsize=10)
        )
        for at in autotexts:
            at.set_color(self.bg_color)
            at.set_fontweight("bold")

        ax.set_title("MITRE ATT&CK Tactical Distribution", fontsize=12, pad=12, fontweight="bold", color=self.text_color)
        fig.tight_layout()

        output_path = self.output_dir / "mitre_tactics.png"
        fig.savefig(output_path, facecolor=fig.get_facecolor(), bbox_inches="tight")
        plt.close(fig)
        return str(output_path)

    def plot_risk_matrix(self) -> str:
        """5x5 Likelihood vs Impact Risk Assessment Heatmap."""
        fig, ax = plt.subplots(figsize=(7.8, 5.0), dpi=150)
        self._apply_theme(fig, ax)

        # 5x5 matrix scoring grid
        # 1: Very Low, 2: Low, 3: Medium, 4: High, 5: Very High
        grid = np.zeros((5, 5))
        for r in range(5):
            for c in range(5):
                grid[r, c] = (r + 1) * (c + 1)

        # Colormap from green (low risk) to yellow to red (high risk)
        cmap = plt.cm.get_cmap("RdYlGn_r")
        im = ax.imshow(grid, cmap=cmap, origin="lower", alpha=0.85, aspect="auto")

        # Map our 5 specific risks onto coordinates (Impact - 1, Likelihood - 1)
        # RSK-01: Likelihood 2, Impact 5 (Escapes) -> x=4, y=1
        # RSK-02: Likelihood 2, Impact 4 (Pivot) -> x=3, y=1
        # RSK-03: Likelihood 4, Impact 4 (Creds) -> x=3, y=3
        # RSK-04: Likelihood 3, Impact 3 (DoS) -> x=2, y=2
        # RSK-05: Likelihood 4, Impact 2 (Alert Fatigue) -> x=1, y=3
        risks_to_plot = [
            ("RSK-01", 1, 4),  # Likelihood 2 (idx 1), Impact 5 (idx 4)
            ("RSK-02", 1, 3),  # Likelihood 2 (idx 1), Impact 4 (idx 3)
            ("RSK-03", 3, 3),  # Likelihood 4 (idx 3), Impact 4 (idx 3)
            ("RSK-04", 2, 2),  # Likelihood 3 (idx 2), Impact 3 (idx 2)
            ("RSK-05", 3, 1),  # Likelihood 4 (idx 3), Impact 2 (idx 1)
        ]

        for code, l_idx, i_idx in risks_to_plot:
            ax.plot(l_idx, i_idx, marker="o", markersize=14, color="#ffffff", markeredgecolor="#0f172a", markeredgewidth=2)
            ax.text(l_idx, i_idx, code.split("-")[1], color="#0f172a", ha="center", va="center", fontweight="bold", fontsize=7.5)

        ax.set_xticks(range(5))
        ax.set_xticklabels(["1: Very Low", "2: Low", "3: Medium", "4: High", "5: Very High"], fontsize=8.5)
        ax.set_yticks(range(5))
        ax.set_yticklabels(["1: Very Low", "2: Low", "3: Medium", "4: High", "5: Very High"], fontsize=8.5)

        ax.set_xlabel("Likelihood (Probability)", fontsize=10, labelpad=8)
        ax.set_ylabel("Impact (Consequence Severity)", fontsize=10, labelpad=8)
        ax.set_title("ISO 27001 ISMS 5x5 Qualitative Risk Matrix", fontsize=12, pad=12, fontweight="bold")

        fig.tight_layout()
        output_path = self.output_dir / "risk_matrix_heatmap.png"
        fig.savefig(output_path, facecolor=fig.get_facecolor(), bbox_inches="tight")
        plt.close(fig)
        return str(output_path)
