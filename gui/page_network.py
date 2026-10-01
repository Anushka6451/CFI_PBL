"""
Network Page — WannaCry Forensic Lab
Hospital network diagram, machine status cards, baseline capture, file viewer.
"""

import tkinter as tk
import customtkinter as ctk
import threading
from gui.theme import COLORS, FONTS, BUTTON_STYLES, STATUS_COLORS
from gui.widgets import MachineCard, SectionFrame, EventConsole


class NetworkPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self.app = app
        self.machine_cards = {}
        self._build_ui()

    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_darkest"],
                           corner_radius=0, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="🏥  HOSPITAL NETWORK — NHS TRUST SIMULATION",
                     font=FONTS["heading"],
                     text_color=COLORS["accent_cyan"]).pack(side="left", padx=20, pady=14)

        # ── Body ──────────────────────────────────────────────────────────────
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        # Left: machines + network diagram
        left = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                            corner_radius=10, border_color=COLORS["border"],
                            border_width=1)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ctk.CTkLabel(left, text="NETWORK TOPOLOGY",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 8))

        # Machine cards
        cards_frame = ctk.CTkFrame(left, fg_color="transparent")
        cards_frame.pack(fill="x", padx=16)

        machines = [
            ("PC-01", "HOSPITAL-PC-01", "192.168.56.10"),
            ("PC-02", "HOSPITAL-PC-02", "192.168.56.20"),
            ("PC-03", "HOSPITAL-PC-03", "192.168.56.30"),
        ]
        for pc_id, name, ip in machines:
            card = MachineCard(cards_frame, pc_id, name, ip, width=200, height=100)
            card.pack(pady=6, padx=8, fill="x")
            self.machine_cards[pc_id] = card

        # Network diagram (text art)
        diag_frame = ctk.CTkFrame(left, fg_color=COLORS["bg_darkest"],
                                  corner_radius=6)
        diag_frame.pack(fill="x", padx=16, pady=12)
        ctk.CTkLabel(diag_frame,
                     text=(
                         "NETWORK DIAGRAM\n\n"
                         "PC-01 ────────── PC-02\n"
                         "  │                  │\n"
                         "  └────── PC-03 ─────┘\n\n"
                         "Subnet: 192.168.56.0/24\n"
                         "Switch: NHS-SW-01\n"
                         "Protocol: SMBv1 (legacy)"
                     ),
                     font=("Courier New", 11),
                     text_color=COLORS["text_secondary"],
                     justify="left").pack(padx=12, pady=10)

        # Buttons
        btn_frame = ctk.CTkFrame(left, fg_color="transparent")
        btn_frame.pack(fill="x", padx=16, pady=(0, 14))

        ctk.CTkButton(btn_frame, text="🏗  SETUP HOSPITAL ENVIRONMENT",
                      command=self._setup_environment,
                      **BUTTON_STYLES["primary"]).pack(fill="x", pady=4)
        ctk.CTkButton(btn_frame, text="📸  CAPTURE BASELINE",
                      command=self._capture_baseline,
                      **BUTTON_STYLES["secondary"]).pack(fill="x", pady=4)
        ctk.CTkButton(btn_frame, text="▶  GO TO SIMULATION",
                      command=lambda: self.app.show_page("simulation"),
                      **BUTTON_STYLES["warning"]).pack(fill="x", pady=4)

        # Right: file viewer
        right = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                             corner_radius=10, border_color=COLORS["border"],
                             border_width=1)
        right.grid(row=0, column=1, sticky="nsew")

        ctk.CTkLabel(right, text="FILE SYSTEM VIEWER",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 4))

        self.status_lbl = ctk.CTkLabel(right, text="Setup the hospital environment first.",
                                       font=("Consolas", 11),
                                       text_color=COLORS["text_secondary"])
        self.status_lbl.pack(pady=4)

        # Filter row
        filter_row = ctk.CTkFrame(right, fg_color="transparent")
        filter_row.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(filter_row, text="Machine:",
                     font=FONTS["small"],
                     text_color=COLORS["text_secondary"]).pack(side="left")
        self.pc_filter = ctk.CTkComboBox(filter_row,
                                         values=["ALL", "PC-01", "PC-02", "PC-03"],
                                         command=self._refresh_files,
                                         fg_color=COLORS["bg_input"],
                                         border_color=COLORS["border"],
                                         button_color=COLORS["accent_blue"],
                                         text_color=COLORS["text_primary"],
                                         font=("Consolas", 11))
        self.pc_filter.set("ALL")
        self.pc_filter.pack(side="left", padx=8)

        self.file_count_lbl = ctk.CTkLabel(filter_row, text="",
                                           font=("Consolas", 11),
                                           text_color=COLORS["accent_blue"])
        self.file_count_lbl.pack(side="left", padx=8)

        # Scrollable file list
        self.file_frame = ctk.CTkScrollableFrame(right, fg_color=COLORS["bg_darkest"],
                                                 corner_radius=6)
        self.file_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        # Baseline status
        self.baseline_lbl = ctk.CTkLabel(right, text="",
                                         font=("Consolas", 11, "bold"),
                                         text_color=COLORS["safe"])
        self.baseline_lbl.pack(pady=(0, 8))

    def _setup_environment(self):
        self.status_lbl.configure(text="Setting up hospital environment…",
                                  text_color=COLORS["text_warning"])
        self.update()

        def _run():
            from simulation.hospital_environment import (
                create_hospital_environment, MACHINES
            )
            from database import db_manager
            db_manager.initialize_database()
            db_manager.reset_database()
            created = create_hospital_environment()
            for pc_id in MACHINES:
                db_manager.log_machine_state(pc_id, "SAFE", "Initial state")
            self.after(0, lambda: self._env_done(created))

        threading.Thread(target=_run, daemon=True).start()

    def _env_done(self, created):
        for pc_id, card in self.machine_cards.items():
            card.set_state("SAFE")
        self.status_lbl.configure(
            text=f"✓ Hospital environment ready — {len(created)} files created",
            text_color=COLORS["safe"])
        self._refresh_files()
        self.app.on_environment_ready()
        self.app.log_event(f"Hospital environment created — {len(created)} dummy files", "success")

    def _capture_baseline(self):
        self.baseline_lbl.configure(text="Capturing baseline…",
                                    text_color=COLORS["text_warning"])
        self.update()

        def _run():
            from simulation.hospital_environment import capture_baseline
            records = capture_baseline()
            self.after(0, lambda: self._baseline_done(records))

        threading.Thread(target=_run, daemon=True).start()

    def _baseline_done(self, records):
        self.baseline_lbl.configure(
            text=f"✅  SYSTEM BASELINE CAPTURED — {len(records)} files hashed",
            text_color=COLORS["safe"])
        self.app.on_baseline_captured(records)
        self.app.log_event(f"Baseline captured — {len(records)} files with SHA-256 hashes", "success")

    def _refresh_files(self, *_):
        from simulation.hospital_environment import get_all_lab_files
        pc_filter = self.pc_filter.get()
        machine_filter = None if pc_filter == "ALL" else pc_filter
        files = get_all_lab_files(machine_filter)

        # Clear old
        for w in self.file_frame.winfo_children():
            w.destroy()

        self.file_count_lbl.configure(text=f"{len(files)} files")

        # Group by machine
        by_machine = {}
        for f in files:
            by_machine.setdefault(f["machine"], []).append(f)

        for pc_id, flist in sorted(by_machine.items()):
            # Machine header
            mhdr = ctk.CTkFrame(self.file_frame, fg_color=COLORS["bg_card"],
                                corner_radius=4)
            mhdr.pack(fill="x", pady=(6, 2))
            ctk.CTkLabel(mhdr, text=f"  📁 {pc_id} — HOSPITAL-PC-{pc_id[-2:]}",
                         font=("Consolas", 11, "bold"),
                         text_color=COLORS["accent_blue"]).pack(side="left", padx=8, pady=4)
            ctk.CTkLabel(mhdr, text=f"{len(flist)} files",
                         font=("Consolas", 10),
                         text_color=COLORS["text_secondary"]).pack(side="right", padx=8)

            for f in sorted(flist, key=lambda x: x["filename"]):
                row = ctk.CTkFrame(self.file_frame, fg_color=COLORS["bg_card2"],
                                   corner_radius=3)
                row.pack(fill="x", pady=1, padx=8)

                # Color based on type
                if f["is_affected"]:
                    icon, clr = "🔴", COLORS["compromised"]
                elif f["is_ransom"]:
                    icon, clr = "⚠", COLORS["accent_yellow"]
                elif f["is_marker"]:
                    icon, clr = "🔍", COLORS["accent_orange"]
                else:
                    icon, clr = "📄", COLORS["text_primary"]

                ctk.CTkLabel(row, text=f"  {icon} {f['filename']}",
                             font=("Consolas", 10),
                             text_color=clr, anchor="w").pack(side="left",
                                                               padx=4, pady=3)
                ctk.CTkLabel(row, text=f"{f['file_size']}B",
                             font=("Courier New", 9),
                             text_color=COLORS["text_dim"]).pack(side="right", padx=8)

    def update_machine_state(self, pc_id: str, state: str):
        if pc_id in self.machine_cards:
            self.machine_cards[pc_id].set_state(state)

    def refresh(self):
        try:
            self._refresh_files()
        except Exception:
            pass
