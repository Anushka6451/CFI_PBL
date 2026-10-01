"""
Attack Reconstruction Page — WannaCry Forensic Lab
Visual forensic reconstruction of the attack chain.
"""
import tkinter as tk
import customtkinter as ctk
from gui.theme import COLORS, FONTS, BUTTON_STYLES


class ReconstructionPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_darkest"],
                           corner_radius=0, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="🗺  ATTACK RECONSTRUCTION — FORENSIC CHAIN ANALYSIS",
                     font=FONTS["heading"],
                     text_color=COLORS["accent_cyan"]).pack(side="left", padx=20, pady=14)

        toolbar = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"],
                               corner_radius=0, height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)
        ctk.CTkButton(toolbar, text="⟶  Case Findings",
                      command=lambda: self.app.show_page("findings"),
                      **BUTTON_STYLES["primary"], width=160).pack(
            side="right", padx=12, pady=8)
        ctk.CTkButton(toolbar, text="⟵  Timeline",
                      command=lambda: self.app.show_page("timeline"),
                      **BUTTON_STYLES["secondary"], width=120).pack(
            side="right", padx=4, pady=8)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.columnconfigure(0, weight=2)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # Visual reconstruction
        vis = ctk.CTkScrollableFrame(body, fg_color=COLORS["bg_panel"],
                                     corner_radius=10,
                                     border_color=COLORS["border"],
                                     border_width=1)
        vis.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ctk.CTkLabel(vis, text="FORENSIC ATTACK RECONSTRUCTION",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 6))

        # Build the visual chain
        self._build_chain(vis)

        # Right: findings summary loaded from DB
        right = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                             corner_radius=10, border_color=COLORS["border"],
                             border_width=1)
        right.grid(row=0, column=1, sticky="nsew")
        ctk.CTkLabel(right, text="INVESTIGATION FINDINGS",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 6))

        self.findings_box = ctk.CTkTextbox(right,
                                           fg_color=COLORS["bg_darkest"],
                                           text_color=COLORS["text_primary"],
                                           font=("Courier New", 10))
        self.findings_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._load_findings()

    def _build_chain(self, parent):
        stages = [
            ("INITIAL COMPROMISE",
             "Simulated WannaCry dropper executed\non HOSPITAL-PC-01\n[Evidence: infection_marker.json]",
             COLORS["compromised"]),
            ("STAGE 2 — FILE IMPACT",
             "*.WCRY_SIMULATED extension applied\nto all document files on PC-01\n[Evidence: AFFECTED_FILE items]",
             COLORS["affected"]),
            ("STAGE 3 — RANSOM NOTE",
             "WANNACRY_SIMULATION_NOTE.txt\ncreated on PC-01\n[Evidence: RANSOM_NOTE item]",
             COLORS["accent_yellow"]),
            ("STAGE 4 — PROPAGATION",
             "Simulated TCP/445 SMB probe\nPC-01 → PC-02  (192.168.56.20)\nPC-01 → PC-03  (192.168.56.30)\n[Evidence: network_events.csv]",
             COLORS["accent_orange"]),
            ("PC-02 COMPROMISED",
             "File impact + ransom note\nreplicated on PC-02\n[Evidence: E-xxx items on PC-02]",
             COLORS["compromised"]),
            ("PC-03 COMPROMISED",
             "File impact + ransom note\nreplicated on PC-03\n[Evidence: E-xxx items on PC-03]",
             COLORS["compromised"]),
            ("INCIDENT DECLARED",
             "3 hosts compromised\n15+ files affected\n3 ransom notes\n2 SMB propagation events",
             COLORS["sev_critical"]),
        ]

        for i, (title, detail, color) in enumerate(stages):
            # Arrow connector
            if i > 0:
                ctk.CTkLabel(parent, text="│\n▼",
                             font=("Courier New", 14),
                             text_color=color).pack()

            box = ctk.CTkFrame(parent,
                               fg_color=COLORS["bg_card"],
                               border_color=color,
                               border_width=2,
                               corner_radius=8)
            box.pack(fill="x", padx=20, pady=2)

            ctk.CTkLabel(box, text=title,
                         font=("Consolas", 12, "bold"),
                         text_color=color).pack(pady=(8, 2))
            ctk.CTkLabel(box, text=detail,
                         font=("Consolas", 9),
                         text_color=COLORS["text_secondary"],
                         justify="left").pack(padx=16, pady=(0, 8))

        # Final status
        ctk.CTkLabel(parent, text="\n│\n▼",
                     font=("Courier New", 14),
                     text_color=COLORS["safe"]).pack()
        final = ctk.CTkFrame(parent, fg_color="#0A1A0A",
                             border_color=COLORS["safe"],
                             border_width=2, corner_radius=8)
        final.pack(fill="x", padx=20, pady=(2, 16))
        ctk.CTkLabel(final,
                     text="CONTAINMENT → RECOVERY → PREVENTION",
                     font=("Consolas", 11, "bold"),
                     text_color=COLORS["safe"]).pack(pady=8)

    def _load_findings(self):
        from forensics.timeline import build_investigation_summary
        try:
            s = build_investigation_summary()
        except Exception:
            s = {}

        self.findings_box.configure(state="normal")
        self.findings_box.delete("1.0", "end")

        self.findings_box.insert("end", "CASE FINDINGS SUMMARY\n")
        self.findings_box.insert("end", "=" * 36 + "\n\n")
        self.findings_box.insert("end",
            f"INITIAL HOST:\n  {s.get('initial_host', '—')}\n\n"
            f"AFFECTED HOSTS:\n  {s.get('affected_hosts', '—')}\n\n"
            f"FILE INDICATOR:\n  {s.get('primary_file_indicator', '—')}\n\n"
            f"NETWORK INDICATOR:\n  {s.get('network_indicator', '—')}\n\n"
            f"RANSOMWARE NOTE:\n  {s.get('ransomware_indicator', '—')}\n\n"
            f"ATTACK SEQUENCE:\n"
        )
        for step in s.get("attack_sequence", []):
            self.findings_box.insert("end", f"  → {step}\n")

        self.findings_box.insert("end",
            f"\nATTRIBUTION:\n  {s.get('attribution', '—')}\n"
        )
        self.findings_box.configure(state="disabled")
        self.app.mark_step(12, done=True)

    def refresh(self):
        self._load_findings()
