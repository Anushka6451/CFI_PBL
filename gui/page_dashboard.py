"""
Dashboard Page — WannaCry Forensic Lab
Main landing screen with workflow overview and quick stats.
"""

import tkinter as tk
import customtkinter as ctk
from datetime import datetime
from gui.theme import COLORS, FONTS, BUTTON_STYLES
from gui.widgets import SectionFrame, ProgressStep, EventConsole


class DashboardPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_darkest"],
                           corner_radius=0, height=90)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        ctk.CTkLabel(hdr,
                     text="⚠  WannaCry Forensic Investigation Lab",
                     font=("Consolas", 24, "bold"),
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 2))
        ctk.CTkLabel(hdr,
                     text="Cyber Terrorism Incident Simulation & Digital Forensics  ·  NHS 2017 Case Study",
                     font=("Consolas", 12),
                     text_color=COLORS["text_secondary"]).pack()

        # ── Main body ─────────────────────────────────────────────────────────
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=16)
        body.columnconfigure(0, weight=2)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # Left: workflow steps
        left = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                            corner_radius=10, border_color=COLORS["border"],
                            border_width=1)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ctk.CTkLabel(left, text="INVESTIGATION WORKFLOW",
                     font=FONTS["heading"],
                     text_color=COLORS["accent_blue"]).pack(pady=(16, 12))

        self.steps = []
        workflow = [
            "Normal Hospital Environment",
            "Capture Pre-Incident Baseline",
            "Launch WannaCry Simulation",
            "Stage 1 — Initial Infection",
            "Stage 2 — File Impact",
            "Stage 3 — Ransom Note",
            "Stage 4 — Worm Propagation",
            "Incident Detection",
            "Evidence Collection",
            "File & Network Forensics",
            "Hash Verification",
            "Timeline Reconstruction",
            "Attack Reconstruction",
            "Containment",
            "Recovery",
            "Mitigation & Prevention",
            "Case Analysis Report",
        ]
        steps_frame = ctk.CTkScrollableFrame(left, fg_color="transparent")
        steps_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        for i, label in enumerate(workflow, 1):
            step = ProgressStep(steps_frame, i, label)
            step.pack(fill="x", pady=3)
            self.steps.append(step)

        # Right column
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        # Case info
        info_frame = SectionFrame(right, "CASE INFORMATION",
                                  border_color=COLORS["accent_cyan"])
        info_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))

        rows = [
            ("Case ID",        "WCL-2017-NHS-001"),
            ("Incident",       "WannaCry Ransomware"),
            ("Date (sim.)",    "12 May 2017"),
            ("Organisation",   "NHS UK (Simulated)"),
            ("Analyst",        "Forensic Lab System"),
            ("Classification", "EDUCATIONAL SIMULATION"),
        ]
        for label, val in rows:
            f = ctk.CTkFrame(info_frame, fg_color="transparent")
            f.pack(fill="x", padx=14, pady=3)
            ctk.CTkLabel(f, text=label + ":",
                         font=("Consolas", 10),
                         text_color=COLORS["text_secondary"],
                         width=120, anchor="w").pack(side="left")
            ctk.CTkLabel(f, text=val,
                         font=("Consolas", 10, "bold"),
                         text_color=COLORS["text_primary"],
                         anchor="w").pack(side="left", padx=(4, 0))

        # Safety notice
        notice = SectionFrame(right, "⚠  SAFETY NOTICE",
                              border_color=COLORS["accent_yellow"])
        notice.grid(row=1, column=0, sticky="nsew")

        notice_text = (
            "EDUCATIONAL SANDBOX\n"
            "NO REAL MALWARE\n\n"
            "This application simulates a\n"
            "WannaCry-style incident for\n"
            "academic forensic training.\n\n"
            "✓ No real encryption used\n"
            "✓ No real network attacks\n"
            "✓ No real system modifications\n"
            "✓ All files confined to:\n"
            "  simulation_lab/\n\n"
            "Files outside the sandbox\n"
            "are NEVER touched."
        )
        ctk.CTkLabel(notice, text=notice_text,
                     font=("Consolas", 10),
                     text_color=COLORS["text_warning"],
                     justify="left").pack(padx=14, pady=(0, 14))

        # ── Bottom: Start button ──────────────────────────────────────────────
        btn_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_darkest"],
                                 corner_radius=0, height=70)
        btn_frame.pack(fill="x", side="bottom")
        btn_frame.pack_propagate(False)

        ctk.CTkButton(btn_frame,
                      text="▶  ENTER FORENSIC LAB",
                      command=lambda: self.app.show_page("network"),
                      **BUTTON_STYLES["primary"],
                      width=280).pack(side="left", padx=20, pady=14)

        self.status_lbl = ctk.CTkLabel(btn_frame,
                                       text="Ready — set up the hospital environment to begin.",
                                       font=("Consolas", 11),
                                       text_color=COLORS["text_secondary"])
        self.status_lbl.pack(side="left", padx=10)

    def mark_step_done(self, step_idx: int):
        """Mark workflow step (0-indexed) as complete."""
        if 0 <= step_idx < len(self.steps):
            self.steps[step_idx].set_active(done=True)

    def mark_step_active(self, step_idx: int):
        if 0 <= step_idx < len(self.steps):
            self.steps[step_idx].set_active(done=False)

    def set_status(self, msg: str, color=None):
        self.status_lbl.configure(
            text=msg,
            text_color=color or COLORS["text_secondary"]
        )

    def refresh(self):
        pass
