"""
Containment & Recovery Page — WannaCry Forensic Lab
"""
import tkinter as tk
import customtkinter as ctk
import threading
from gui.theme import COLORS, FONTS, BUTTON_STYLES
from gui.widgets import MachineCard, EventConsole


class ContainmentPage(ctk.CTkFrame):
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
        ctk.CTkLabel(hdr, text="🔒  CONTAINMENT & RECOVERY",
                     font=FONTS["heading"],
                     text_color=COLORS["accent_cyan"]).pack(side="left", padx=20, pady=14)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        # Left: machines + controls
        left = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                            corner_radius=10, border_color=COLORS["border"],
                            border_width=1)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ctk.CTkLabel(left, text="MACHINE STATUS",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 8))

        for pc_id, name, ip in [
            ("PC-01", "HOSPITAL-PC-01", "192.168.56.10"),
            ("PC-02", "HOSPITAL-PC-02", "192.168.56.20"),
            ("PC-03", "HOSPITAL-PC-03", "192.168.56.30"),
        ]:
            card = MachineCard(left, pc_id, name, ip)
            card.pack(padx=16, pady=6, fill="x")
            self.machine_cards[pc_id] = card

        # Containment button
        ctk.CTkButton(left, text="🔒  CONTAIN ALL MACHINES",
                      command=self._contain_all,
                      fg_color="#6B4700",
                      hover_color="#AA7000",
                      text_color="#FFFFFF",
                      font=("Consolas", 13, "bold"),
                      corner_radius=8,
                      height=48).pack(fill="x", padx=16, pady=(12, 4))

        # Recovery button
        ctk.CTkButton(left, text="✅  START RECOVERY",
                      command=self._recover_all,
                      fg_color="#004422",
                      hover_color="#006633",
                      text_color="#FFFFFF",
                      font=("Consolas", 13, "bold"),
                      corner_radius=8,
                      height=48).pack(fill="x", padx=16, pady=4)

        ctk.CTkButton(left, text="⟶  Prevention & Mitigation",
                      command=lambda: self.app.show_page("prevention"),
                      **BUTTON_STYLES["secondary"]).pack(fill="x", padx=16, pady=(8, 14))

        # Right: console + steps
        right = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                             corner_radius=10, border_color=COLORS["border"],
                             border_width=1)
        right.grid(row=0, column=1, sticky="nsew")

        ctk.CTkLabel(right, text="CONTAINMENT / RECOVERY LOG",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 6))

        self.console = EventConsole(right)
        self.console.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        # Recovery explanation
        exp = ctk.CTkFrame(right, fg_color=COLORS["bg_card"],
                           corner_radius=6, border_color=COLORS["safe"],
                           border_width=1)
        exp.pack(fill="x", padx=16, pady=(0, 14))
        ctk.CTkLabel(exp,
                     text=(
                         "RECOVERY METHOD:\n\n"
                         "1. Isolate all affected machines (block simulated propagation)\n"
                         "2. Remove .WCRY_SIMULATED renamed files\n"
                         "3. Restore originals from pre-incident baseline backup\n"
                         "4. Verify restored files match baseline SHA-256 hashes\n"
                         "5. Preserve all collected forensic evidence separately\n\n"
                         "Note: Forensic evidence is NOT deleted during recovery."
                     ),
                     font=("Consolas", 9),
                     text_color=COLORS["text_secondary"],
                     justify="left").pack(padx=12, pady=8)

    def _contain_all(self):
        self.console.append("─" * 50, "dim")
        self.console.append("CONTAINMENT PROCEDURE INITIATED", "critical")
        self.console.append("─" * 50, "dim")

        def _run():
            from simulation.recovery import contain_all_machines
            contain_all_machines(callback=self._on_contain_event)
            self.after(0, self._containment_done)

        threading.Thread(target=_run, daemon=True).start()

    def _on_contain_event(self, event):
        self.after(0, lambda e=event: self._process_contain(e))

    def _process_contain(self, event):
        machine = event.get("machine", "")
        if machine in self.machine_cards:
            self.machine_cards[machine].set_state("ISOLATED")
            self.app.on_machine_state_change(machine, "ISOLATED")
        self.console.append(
            f"  🔒 {event.get('description', '')}",
            "medium")

    def _containment_done(self):
        self.console.append("\n✅ ALL MACHINES ISOLATED", "success")
        self.console.append("Propagation stopped. Network access blocked.", "success")
        self.app.mark_step(13, done=True)
        self.app.log_event("Containment complete — all machines isolated", "success")

    def _recover_all(self):
        self.console.append("\n─" * 50, "dim")
        self.console.append("RECOVERY PROCEDURE INITIATED", "success")
        self.console.append("─" * 50, "dim")
        self.console.append("Restoring files from clean baseline…", "info")

        def _run():
            from simulation.recovery import recover_all_machines
            recover_all_machines(callback=self._on_recover_event)
            self.after(0, self._recovery_done)

        threading.Thread(target=_run, daemon=True).start()

    def _on_recover_event(self, event):
        self.after(0, lambda e=event: self._process_recover(e))

    def _process_recover(self, event):
        machine = event.get("machine", "")
        if machine in self.machine_cards:
            self.machine_cards[machine].set_state("RECOVERED")
            self.app.on_machine_state_change(machine, "RECOVERED")
        files = event.get("files_restored", 0)
        self.console.append(
            f"  ✅ {event.get('description', '')} — {files} files restored",
            "success")

    def _recovery_done(self):
        self.console.append("\n✅ RECOVERY COMPLETE", "success")
        self.console.append("All machines returned to pre-incident state.", "success")
        self.console.append("Forensic evidence preserved in cases/evidence_archive/", "info")
        self.app.mark_step(14, done=True)
        self.app.log_event("Recovery complete — all machines restored", "success")

    def update_machine_state(self, pc_id, state):
        if pc_id in self.machine_cards:
            self.machine_cards[pc_id].set_state(state)

    def refresh(self):
        from database import db_manager
        states = db_manager.get_machine_states()
        for pc_id, info in states.items():
            if pc_id in self.machine_cards:
                self.machine_cards[pc_id].set_state(info.get("state", "SAFE"))
