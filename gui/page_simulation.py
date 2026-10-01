"""
Simulation Page — WannaCry Forensic Lab
Step-by-step attack simulation with live visualization and event console.
"""

import tkinter as tk
import customtkinter as ctk
import threading
import time
from gui.theme import COLORS, FONTS, BUTTON_STYLES, STATUS_COLORS
from gui.widgets import MachineCard, EventConsole, SectionFrame


class SimulationPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self.app = app
        self.machine_cards = {}
        self._affected_count = 0
        self._sim_running = False
        self._build_ui()

    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_darkest"],
                           corner_radius=0, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="💀  WANNACRY SIMULATION — CONTROLLED EDUCATIONAL SANDBOX",
                     font=FONTS["heading"],
                     text_color=COLORS["compromised"]).pack(side="left", padx=20, pady=14)
        self.safe_badge = ctk.CTkLabel(hdr,
                                       text="✓ EDUCATIONAL SANDBOX — NO REAL MALWARE",
                                       font=("Consolas", 11, "bold"),
                                       text_color=COLORS["safe"])
        self.safe_badge.pack(side="right", padx=20)

        # ── Body ──────────────────────────────────────────────────────────────
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        # Left panel — machines + controls
        left = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                            corner_radius=10, border_color=COLORS["border"],
                            border_width=1)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ctk.CTkLabel(left, text="HOSPITAL MACHINES",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 8))

        cards_outer = ctk.CTkFrame(left, fg_color="transparent")
        cards_outer.pack(fill="x", padx=16)

        machines = [
            ("PC-01", "HOSPITAL-PC-01", "192.168.56.10"),
            ("PC-02", "HOSPITAL-PC-02", "192.168.56.20"),
            ("PC-03", "HOSPITAL-PC-03", "192.168.56.30"),
        ]
        for pc_id, name, ip in machines:
            card = MachineCard(cards_outer, pc_id, name, ip,
                               width=220, height=100)
            card.pack(pady=6, padx=4, fill="x")
            self.machine_cards[pc_id] = card

        # Propagation visualizer
        prop_frame = ctk.CTkFrame(left, fg_color=COLORS["bg_darkest"],
                                  corner_radius=6)
        prop_frame.pack(fill="x", padx=16, pady=8)
        self.prop_lbl = ctk.CTkLabel(prop_frame,
                                     text=(
                                         "PROPAGATION MODEL\n\n"
                                         "PC-01\n"
                                         "  │\n"
                                         "  │  TCP/445\n"
                                         "  ├──→ PC-02\n"
                                         "  │\n"
                                         "  └──→ PC-03"
                                     ),
                                     font=("Courier New", 11),
                                     text_color=COLORS["text_dim"],
                                     justify="left")
        self.prop_lbl.pack(padx=12, pady=10)

        # Stats
        stats_frame = ctk.CTkFrame(left, fg_color=COLORS["bg_card"],
                                   corner_radius=6)
        stats_frame.pack(fill="x", padx=16, pady=4)

        self.affected_lbl = ctk.CTkLabel(stats_frame,
                                         text="Affected Files: 0",
                                         font=("Consolas", 13, "bold"),
                                         text_color=COLORS["compromised"])
        self.affected_lbl.pack(pady=6)
        self.stage_lbl = ctk.CTkLabel(stats_frame,
                                      text="Stage: READY",
                                      font=("Consolas", 11),
                                      text_color=COLORS["text_secondary"])
        self.stage_lbl.pack(pady=(0, 6))

        # Progress bar
        self.progress = ctk.CTkProgressBar(left, width=200,
                                           fg_color=COLORS["bg_panel"],
                                           progress_color=COLORS["compromised"])
        self.progress.pack(padx=16, pady=4)
        self.progress.set(0)

        # Main launch button
        self.launch_btn = ctk.CTkButton(
            left,
            text="🚀  LAUNCH CONTROLLED\n    WANNACRY SIMULATION",
            command=self._launch_simulation,
            fg_color="#6B0000",
            hover_color="#AA0000",
            text_color="#FFFFFF",
            font=("Consolas", 14, "bold"),
            corner_radius=8,
            height=64,
        )
        self.launch_btn.pack(fill="x", padx=16, pady=8)

        ctk.CTkButton(left, text="⟶  INVESTIGATION",
                      command=lambda: self.app.show_page("evidence"),
                      **BUTTON_STYLES["secondary"]).pack(fill="x", padx=16, pady=(0, 14))

        # Right panel — live event console
        right = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                             corner_radius=10, border_color=COLORS["border"],
                             border_width=1)
        right.grid(row=0, column=1, sticky="nsew")

        top_bar = ctk.CTkFrame(right, fg_color="transparent")
        top_bar.pack(fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(top_bar, text="⚡  LIVE ATTACK MONITOR",
                     font=FONTS["subhead"],
                     text_color=COLORS["compromised"]).pack(side="left")
        ctk.CTkButton(top_bar, text="Clear",
                      command=lambda: self.console.clear(),
                      **BUTTON_STYLES["secondary"],
                      width=60, height=28).pack(side="right")

        self.console = EventConsole(right)
        self.console.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        # Incident alert frame (hidden initially)
        self.incident_frame = ctk.CTkFrame(right,
                                           fg_color=COLORS["bg_card"],
                                           border_color=COLORS["compromised"],
                                           border_width=2, corner_radius=8)
        self.incident_frame.pack(fill="x", padx=16, pady=(0, 16))

        self.incident_lbl = ctk.CTkLabel(self.incident_frame,
                                         text="",
                                         font=("Consolas", 13, "bold"),
                                         text_color=COLORS["compromised"],
                                         justify="left")
        self.incident_lbl.pack(padx=14, pady=10)

    def _launch_simulation(self):
        if self._sim_running:
            return
        self._sim_running = True
        self._affected_count = 0
        self.launch_btn.configure(state="disabled", text="SIMULATION RUNNING…")
        self.console.clear()
        self.progress.set(0)
        self.console.append("=" * 60, "dim")
        self.console.append("  WANNACRY FORENSIC LAB — CONTROLLED SIMULATION", "header")
        self.console.append("  EDUCATIONAL SANDBOX — NO REAL MALWARE", "success")
        self.console.append("=" * 60, "dim")

        def _run():
            from simulation.incident_simulator import run_full_simulation
            run_full_simulation(event_callback=self._on_sim_event)
            self.after(0, self._simulation_complete)

        threading.Thread(target=_run, daemon=True).start()

    def _on_sim_event(self, event):
        time.sleep(0.8)   # Dramatic pacing — each stage visible to user
        self.after(0, lambda e=event: self._process_event(e))

    def _process_event(self, event):
        etype = event.get("type", "")
        ts = event.get("ts", "")[:8]
        machine = event.get("machine", "")

        if etype == "INITIAL_COMPROMISE":
            self.machine_cards[machine].set_state("COMPROMISED")
            self.stage_lbl.configure(text="Stage 1 — INITIAL INFECTION",
                                     text_color=COLORS["compromised"])
            self.console.append(f"\n[{ts}] 🔴 STAGE 1 — INITIAL INFECTION", "critical")
            self.console.append(f"        {event['description']}", "critical")
            self.console.append(f"        Infection marker: infection_marker.json", "high")
            self.progress.set(0.1)
            self.app.on_machine_state_change(machine, "COMPROMISED")
            self.app.mark_step(3, done=True)

        elif etype == "FILE_IMPACT":
            self._affected_count += 1
            self.affected_lbl.configure(
                text=f"Affected Files: {self._affected_count}")
            self.stage_lbl.configure(text="Stage 2 — FILE IMPACT",
                                     text_color=COLORS["affected"])
            self.console.append(
                f"[{ts}] ⚠  {event['original']} → {event['affected']}", "high")
            self.progress.set(min(0.1 + self._affected_count * 0.02, 0.4))
            self.app.mark_step(4, done=True)

        elif etype == "RANSOM_NOTE":
            self.stage_lbl.configure(text="Stage 3 — RANSOM NOTE",
                                     text_color=COLORS["accent_yellow"])
            self.console.append(
                f"\n[{ts}] 📄 STAGE 3 — RANSOM NOTE CREATED", "medium")
            self.console.append(
                f"        WANNACRY_SIMULATION_NOTE.txt on {machine}", "medium")
            self.progress.set(0.5)
            self.app.mark_step(5, done=True)

        elif etype == "PROPAGATION_ATTEMPT":
            src = event.get("source_ip", "")
            dst = event.get("target_ip", "")
            self.stage_lbl.configure(text="Stage 4 — WORM PROPAGATION",
                                     text_color=COLORS["accent_orange"])
            self.console.append(
                f"\n[{ts}] 🌐 STAGE 4 — SIMULATED PROPAGATION", "high")
            self.console.append(
                f"        {src} → {dst}  TCP/445", "high")
            self._update_propagation_diagram(event.get("source", ""),
                                             event.get("target", ""))
            self.progress.set(0.65)
            self.app.mark_step(6, done=True)

        elif etype == "HOST_COMPROMISED":
            self.machine_cards[machine].set_state("COMPROMISED")
            self.console.append(
                f"[{ts}] 🔴 {machine} COMPROMISED via propagation", "critical")
            self.app.on_machine_state_change(machine, "COMPROMISED")

        elif etype == "INCIDENT_DECLARED":
            self.progress.set(1.0)
            self.stage_lbl.configure(text="🚨 INCIDENT DECLARED",
                                     text_color=COLORS["compromised"])
            self.console.append("\n" + "=" * 60, "critical")
            self.console.append("  🚨 CYBER INCIDENT DECLARED", "critical")
            self.console.append("=" * 60, "critical")
            self._show_incident_alert()
            self.app.mark_step(7, done=True)

    def _update_propagation_diagram(self, source, target):
        self.prop_lbl.configure(
            text=(
                f"PROPAGATION MODEL\n\n"
                f"PC-01  🔴 COMPROMISED\n"
                f"  │\n"
                f"  │  ⟶ TCP/445 SIMULATED\n"
                f"  ├──→ {target}  🔴 COMPROMISED\n"
                f"  │\n"
                f"  └──→ (next target)"
            ),
            text_color=COLORS["compromised"]
        )

    def _show_incident_alert(self):
        from database import db_manager
        file_impacts = db_manager.get_file_impacts()
        net_events = db_manager.get_network_events()
        self.incident_lbl.configure(
            text=(
                "🚨  CYBER INCIDENT DETECTED\n\n"
                f"  ▸ {len(self.machine_cards)} compromised hosts\n"
                f"  ▸ {len(file_impacts)} affected files\n"
                f"  ▸ 1 ransomware-style signature\n"
                f"  ▸ {len(net_events)} simulated SMB propagation events\n"
                f"  ▸ 3 ransom notes"
            )
        )

    def _simulation_complete(self):
        self._sim_running = False
        self.launch_btn.configure(
            state="normal",
            text="🔄  RE-RUN SIMULATION",
            fg_color="#1E3A5F",
        )
        self.app.on_simulation_complete()
        self.app.log_event("WannaCry simulation complete — begin forensic investigation", "success")

    def update_machine_state(self, pc_id: str, state: str):
        if pc_id in self.machine_cards:
            self.machine_cards[pc_id].set_state(state)

    def refresh(self):
        pass
