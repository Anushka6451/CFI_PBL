"""
Prevention & Mitigation Page — WannaCry Forensic Lab
Shows defensive controls and runs the protected second simulation.
"""
import tkinter as tk
import customtkinter as ctk
import threading
import time
from gui.theme import COLORS, FONTS, BUTTON_STYLES
from gui.widgets import MachineCard, EventConsole


class PreventionPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self.app = app
        self.machine_cards = {}
        self._build_ui()

    def _build_ui(self):
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_darkest"],
                           corner_radius=0, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="🛡  PREVENTION & MITIGATION — SECOND PROTECTED SIMULATION",
                     font=FONTS["heading"],
                     text_color=COLORS["safe"]).pack(side="left", padx=20, pady=14)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.columnconfigure(2, weight=2)
        body.rowconfigure(0, weight=1)

        # Mitigation list
        mit = ctk.CTkScrollableFrame(body, fg_color=COLORS["bg_panel"],
                                     corner_radius=10,
                                     border_color=COLORS["safe"],
                                     border_width=1)
        mit.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        ctk.CTkLabel(mit, text="MITIGATIONS APPLIED",
                     font=FONTS["subhead"],
                     text_color=COLORS["safe"]).pack(pady=(14, 8))

        controls = [
            ("🔧", "MS17-010 Patch Applied",
             "Windows security update installed\non all systems"),
            ("🚫", "SMBv1 Disabled",
             "Legacy SMBv1 protocol disabled\nvia Group Policy"),
            ("🔒", "Network Segmentation",
             "VLANs configured — clinical\nsystems isolated"),
            ("🛡", "Endpoint Protection",
             "Antivirus + EDR deployed\non all endpoints"),
            ("💾", "Offline Backups",
             "Daily offline backups verified\nand stored securely"),
            ("📊", "Continuous Monitoring",
             "SIEM alerts configured for\nanomalous SMB activity"),
            ("📋", "Incident Response Plan",
             "IR procedures documented\nand team trained"),
        ]

        for emoji, title, detail in controls:
            box = ctk.CTkFrame(mit, fg_color=COLORS["bg_card"],
                               border_color=COLORS["safe"],
                               border_width=1, corner_radius=6)
            box.pack(fill="x", padx=12, pady=4)
            ctk.CTkLabel(box, text=f"{emoji}  {title}",
                         font=("Consolas", 11, "bold"),
                         text_color=COLORS["safe"]).pack(anchor="w", padx=10, pady=(6, 0))
            ctk.CTkLabel(box, text=detail,
                         font=("Consolas", 9),
                         text_color=COLORS["text_secondary"],
                         justify="left").pack(anchor="w", padx=10, pady=(0, 6))

        # Machine status
        machines_frame = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                                      corner_radius=10,
                                      border_color=COLORS["border"],
                                      border_width=1)
        machines_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 8))

        ctk.CTkLabel(machines_frame, text="MACHINE STATUS",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 8))

        for pc_id, name, ip in [
            ("PC-01", "HOSPITAL-PC-01", "192.168.56.10"),
            ("PC-02", "HOSPITAL-PC-02", "192.168.56.20"),
            ("PC-03", "HOSPITAL-PC-03", "192.168.56.30"),
        ]:
            card = MachineCard(machines_frame, pc_id, name, ip)
            card.pack(padx=16, pady=6, fill="x")
            self.machine_cards[pc_id] = card

        # Rebuild environment & run protected sim
        ctk.CTkButton(machines_frame,
                      text="🔄  SETUP & RUN PROTECTED\n    SIMULATION",
                      command=self._run_protected,
                      fg_color="#003344",
                      hover_color="#005566",
                      text_color="#FFFFFF",
                      font=("Consolas", 13, "bold"),
                      corner_radius=8,
                      height=56).pack(fill="x", padx=16, pady=8)

        ctk.CTkButton(machines_frame, text="⟶  Case Analysis",
                      command=lambda: self.app.show_page("case_analysis"),
                      **BUTTON_STYLES["secondary"]).pack(fill="x", padx=16, pady=(0, 14))

        # Console
        right = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                             corner_radius=10, border_color=COLORS["border"],
                             border_width=1)
        right.grid(row=0, column=2, sticky="nsew")

        ctk.CTkLabel(right, text="PROTECTED SIMULATION MONITOR",
                     font=FONTS["subhead"],
                     text_color=COLORS["safe"]).pack(pady=(14, 6))

        self.console = EventConsole(right)
        self.console.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        # Key outcome notice
        outcome = ctk.CTkFrame(right, fg_color=COLORS["bg_card"],
                               border_color=COLORS["safe"],
                               border_width=1, corner_radius=6)
        outcome.pack(fill="x", padx=16, pady=(0, 14))
        ctk.CTkLabel(outcome,
                     text=(
                         "EXPECTED OUTCOME:\n\n"
                         "PC-01 — Still compromised (initial entry point)\n"
                         "PC-02 — PROTECTED (propagation blocked)\n"
                         "PC-03 — PROTECTED (propagation blocked)\n\n"
                         "Security controls prevent worm spread\n"
                         "even when initial infection occurs."
                     ),
                     font=("Consolas", 9),
                     text_color=COLORS["text_secondary"],
                     justify="left").pack(padx=10, pady=8)

    def _run_protected(self):
        self.console.clear()
        self.console.append("=" * 55, "dim")
        self.console.append("  PROTECTED SIMULATION — SECURITY CONTROLS ACTIVE", "success")
        self.console.append("=" * 55, "dim")

        # Reset machines
        for card in self.machine_cards.values():
            card.set_state("SAFE")

        def _run():
            # First rebuild the hospital environment for a clean slate
            from simulation.hospital_environment import (
                create_hospital_environment, capture_baseline, MACHINES
            )
            from database import db_manager
            create_hospital_environment()
            capture_baseline()
            for pc_id in MACHINES:
                db_manager.log_machine_state(pc_id, "SAFE", "Protected simulation start")

            from simulation.incident_simulator import run_protected_simulation
            run_protected_simulation(event_callback=self._on_prot_event)
            self.after(0, self._protected_done)

        threading.Thread(target=_run, daemon=True).start()

    def _on_prot_event(self, event):
        time.sleep(0.9)
        self.after(0, lambda e=event: self._process_prot_event(e))

    def _process_prot_event(self, event):
        etype = event.get("type", "")
        machine = event.get("machine", "")
        ts = event.get("ts", "")[:8]

        if etype == "INITIAL_COMPROMISE":
            self.machine_cards["PC-01"].set_state("COMPROMISED")
            self.console.append(
                f"\n[{ts}] 🔴 PC-01 COMPROMISED — initial entry point", "critical")

        elif etype == "FILE_IMPACT":
            self.console.append(
                f"[{ts}] ⚠  File affected on PC-01 (isolated to entry point)", "high")

        elif etype == "RANSOM_NOTE":
            self.console.append(
                f"[{ts}] 📄 Ransom note on PC-01 only", "medium")

        elif etype == "PROPAGATION_BLOCKED":
            target = event.get("target", machine)
            if target in self.machine_cards:
                self.machine_cards[target].set_state("PROTECTED")
            self.console.append(
                f"\n[{ts}] 🛡  SECURITY CONTROL BLOCKED PROPAGATION", "success")
            self.console.append(
                f"        → {target} remains SAFE (patch + SMBv1 disabled)", "success")

        elif etype == "AUTO_ISOLATED":
            self.machine_cards["PC-01"].set_state("ISOLATED")
            self.console.append(
                f"\n[{ts}] 🔒 PC-01 automatically isolated by endpoint protection", "info")

    def _protected_done(self):
        self.console.append("\n" + "=" * 55, "success")
        self.console.append("  ✅ PROTECTED SIMULATION COMPLETE", "success")
        self.console.append("=" * 55, "success")
        self.console.append("\nRESULT:", "success")
        self.console.append("  PC-01: COMPROMISED + ISOLATED", "high")
        self.console.append("  PC-02: PROTECTED ✓", "success")
        self.console.append("  PC-03: PROTECTED ✓", "success")
        self.console.append("\nSecurity controls successfully limited blast radius.", "success")
        self.app.mark_step(15, done=True)
        self.app.log_event("Protected simulation complete — propagation blocked by security controls", "success")

    def refresh(self):
        pass
