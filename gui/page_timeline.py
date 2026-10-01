"""
Timeline Page — WannaCry Forensic Lab
Reconstructed attack timeline from correlated evidence sources.
"""
import tkinter as tk
import customtkinter as ctk
import threading
from gui.theme import COLORS, FONTS, BUTTON_STYLES


class TimelinePage(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_darkest"],
                           corner_radius=0, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="📅  ATTACK TIMELINE RECONSTRUCTION",
                     font=FONTS["heading"],
                     text_color=COLORS["accent_cyan"]).pack(side="left", padx=20, pady=14)

        toolbar = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"],
                               corner_radius=0, height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        ctk.CTkButton(toolbar, text="🔄  RECONSTRUCT TIMELINE",
                      command=self._reconstruct,
                      **BUTTON_STYLES["primary"], width=220).pack(
            side="left", padx=12, pady=8)
        ctk.CTkButton(toolbar, text="⟶  Attack Reconstruction",
                      command=lambda: self.app.show_page("reconstruction"),
                      **BUTTON_STYLES["secondary"], width=200).pack(
            side="right", padx=12, pady=8)

        self.stats_lbl = ctk.CTkLabel(toolbar, text="",
                                      font=("Consolas", 11),
                                      text_color=COLORS["accent_blue"])
        self.stats_lbl.pack(side="left", padx=12)

        # Method note
        method = ctk.CTkFrame(self, fg_color=COLORS["bg_card"],
                              corner_radius=0)
        method.pack(fill="x", padx=0)
        ctk.CTkLabel(method,
                     text=(
                         "  Timeline sources: endpoint_events.csv  +  network_events.csv  "
                         "+  file metadata  +  infection markers  +  ransom notes  "
                         "→  sorted and correlated"
                     ),
                     font=("Consolas", 9),
                     text_color=COLORS["text_secondary"]).pack(pady=4, padx=20, anchor="w")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.columnconfigure(0, weight=2)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # Timeline scroll
        left = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                            corner_radius=10, border_color=COLORS["border"],
                            border_width=1)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        ctk.CTkLabel(left, text="RECONSTRUCTED ATTACK TIMELINE",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 6))

        self.timeline_scroll = ctk.CTkScrollableFrame(left, fg_color=COLORS["bg_darkest"])
        self.timeline_scroll.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # Right: finding summary
        right = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                             corner_radius=10, border_color=COLORS["border"],
                             border_width=1)
        right.grid(row=0, column=1, sticky="nsew")
        ctk.CTkLabel(right, text="TIMELINE LEGEND",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 8))

        legend = [
            ("🔴", "CRITICAL", COLORS["compromised"]),
            ("⚠️", "HIGH",     COLORS["affected"]),
            ("🟡", "MEDIUM",   COLORS["accent_yellow"]),
            ("🔵", "INFO",     COLORS["accent_blue"]),
            ("✅", "SUCCESS",  COLORS["safe"]),
        ]
        for emoji, label, color in legend:
            row = ctk.CTkFrame(right, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=3)
            ctk.CTkLabel(row, text=f"{emoji}  {label}",
                         font=("Consolas", 11),
                         text_color=color).pack(side="left")

        ctk.CTkLabel(right, text="\nEVIDENCE SOURCES",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(8, 4))

        sources = [
            "endpoint_events.csv",
            "network_events.csv",
            "infection_marker.json",
            "WANNACRY_SIMULATION_NOTE.txt",
            "File impact records",
            "Machine state logs",
        ]
        for s in sources:
            ctk.CTkLabel(right, text=f"  📄 {s}",
                         font=("Consolas", 9),
                         text_color=COLORS["text_secondary"],
                         anchor="w").pack(fill="x", padx=16, pady=2)

        self.finding_box = ctk.CTkTextbox(right,
                                          fg_color=COLORS["bg_darkest"],
                                          text_color=COLORS["text_primary"],
                                          font=("Courier New", 10),
                                          height=180)
        self.finding_box.pack(fill="x", padx=12, pady=12)
        self.finding_box.configure(state="disabled")

    def _reconstruct(self):
        def _run():
            from forensics.timeline import reconstruct_timeline
            timeline = reconstruct_timeline()
            self.after(0, lambda: self._show_timeline(timeline))

        threading.Thread(target=_run, daemon=True).start()

    def _show_timeline(self, timeline):
        for w in self.timeline_scroll.winfo_children():
            w.destroy()

        self.stats_lbl.configure(
            text=f"{len(timeline)} timeline events reconstructed from evidence")

        for i, event in enumerate(timeline):
            self._add_timeline_entry(event, i)

        # Finding
        self.finding_box.configure(state="normal")
        self.finding_box.delete("1.0", "end")
        self.finding_box.insert("end",
            "INVESTIGATOR CONCLUSION:\n\n"
            "Timeline reconstructed by correlating timestamps from:\n"
            "• Endpoint event logs\n"
            "• Synthetic network captures\n"
            "• File modification metadata\n"
            "• Infection markers\n"
            "• Ransom note creation times\n\n"
            "The sequence of events is consistent with a\n"
            "WannaCry-style ransomware incident:\n"
            "initial compromise → file impact → ransom note\n"
            "→ worm propagation → multi-host infection."
        )
        self.finding_box.configure(state="disabled")

        self.app.mark_step(11, done=True)
        self.app.log_event(f"Timeline reconstructed — {len(timeline)} events correlated", "success")

    def _add_timeline_entry(self, event, idx):
        sig = event.get("significance", "INFO")
        color_map = {
            "HIGH":   COLORS["compromised"],
            "MEDIUM": COLORS["accent_yellow"],
            "INFO":   COLORS["accent_blue"],
        }
        border_color = color_map.get(sig, COLORS["border"])

        # Container
        outer = ctk.CTkFrame(self.timeline_scroll,
                             fg_color="transparent")
        outer.pack(fill="x", pady=3)

        # Left time column
        time_col = ctk.CTkFrame(outer, fg_color="transparent", width=80)
        time_col.pack(side="left")
        time_col.pack_propagate(False)

        ts = str(event.get("ts", ""))
        time_str = ts[11:19] if "T" in ts else ts[:8]
        ctk.CTkLabel(time_col, text=time_str,
                     font=("Courier New", 10),
                     text_color=COLORS["text_secondary"]).pack(pady=8)

        # Connector line
        ctk.CTkLabel(outer, text="┃",
                     font=("Consolas", 20),
                     text_color=border_color,
                     width=16).pack(side="left")

        # Event card
        card = ctk.CTkFrame(outer, fg_color=COLORS["bg_card"],
                            border_color=border_color,
                            border_width=1, corner_radius=6)
        card.pack(side="left", fill="x", expand=True, padx=(4, 0))

        desc = event.get("description", "")
        ctk.CTkLabel(card, text=desc,
                     font=("Consolas", 10),
                     text_color=COLORS["text_primary"],
                     anchor="w", justify="left",
                     wraplength=380).pack(side="left", padx=10, pady=6)

        eids = event.get("evidence_ids", "")
        if eids:
            ctk.CTkLabel(card, text=f"[{eids}]",
                         font=("Consolas", 8),
                         text_color=COLORS["accent_cyan"]).pack(
                side="right", padx=8)

    def refresh(self):
        pass
