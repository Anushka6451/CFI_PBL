"""
Network Forensics Page — WannaCry Forensic Lab
"""
import tkinter as tk
import customtkinter as ctk
import threading
from gui.theme import COLORS, FONTS, BUTTON_STYLES


class NetworkForensicsPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self.app = app
        self._all_traffic = []
        self._build_ui()

    def _build_ui(self):
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_darkest"],
                           corner_radius=0, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="🌐  NETWORK FORENSICS — SYNTHETIC TRAFFIC ANALYSIS",
                     font=FONTS["heading"],
                     text_color=COLORS["accent_cyan"]).pack(side="left", padx=20, pady=14)

        toolbar = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"],
                               corner_radius=0, height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        ctk.CTkButton(toolbar, text="📡  ANALYZE NETWORK TRAFFIC",
                      command=self._analyze,
                      **BUTTON_STYLES["primary"], width=220).pack(
            side="left", padx=12, pady=8)

        ctk.CTkLabel(toolbar, text="Port filter:",
                     font=FONTS["small"],
                     text_color=COLORS["text_secondary"]).pack(side="left", padx=(10, 0))
        self.port_filter = ctk.CTkEntry(toolbar, width=80,
                                         fg_color=COLORS["bg_input"],
                                         border_color=COLORS["border"],
                                         text_color=COLORS["text_primary"],
                                         font=("Consolas", 11),
                                         placeholder_text="445")
        self.port_filter.pack(side="left", padx=6)
        ctk.CTkButton(toolbar, text="Filter", command=self._apply_port_filter,
                      **BUTTON_STYLES["secondary"], width=70,
                      height=32).pack(side="left", padx=4)

        ctk.CTkButton(toolbar, text="⟶  Hash Verify",
                      command=lambda: self.app.show_page("hash"),
                      **BUTTON_STYLES["secondary"], width=130).pack(
            side="right", padx=12, pady=8)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        # Traffic table
        left = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                            corner_radius=10, border_color=COLORS["border"],
                            border_width=1)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ctk.CTkLabel(left, text="SYNTHETIC NETWORK CAPTURE",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 6))

        # Table header
        th = ctk.CTkFrame(left, fg_color=COLORS["bg_darkest"])
        th.pack(fill="x", padx=12)
        for col, w in [("Time", 100), ("Source", 130), ("Destination", 130),
                        ("Port", 55), ("Protocol", 90), ("Event", 130)]:
            ctk.CTkLabel(th, text=col, font=("Consolas", 10, "bold"),
                         text_color=COLORS["accent_blue"],
                         width=w, anchor="w").pack(side="left", padx=3, pady=5)

        self.traffic_frame = ctk.CTkScrollableFrame(left, fg_color=COLORS["bg_darkest"])
        self.traffic_frame.pack(fill="both", expand=True, padx=12, pady=(2, 12))

        # Analysis panel
        right = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                             corner_radius=10, border_color=COLORS["border"],
                             border_width=1)
        right.grid(row=0, column=1, sticky="nsew")

        ctk.CTkLabel(right, text="SMB PATTERN ANALYSIS",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 6))

        self.analysis_box = ctk.CTkTextbox(right,
                                           fg_color=COLORS["bg_darkest"],
                                           text_color=COLORS["text_primary"],
                                           font=("Courier New", 11))
        self.analysis_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.analysis_box.configure(state="disabled")

        # Caution note
        note = ctk.CTkFrame(right, fg_color=COLORS["bg_card"],
                            corner_radius=6, border_color=COLORS["accent_yellow"],
                            border_width=1)
        note.pack(fill="x", padx=12, pady=(0, 12))
        ctk.CTkLabel(note,
                     text=(
                         "⚠  INVESTIGATOR NOTE\n\n"
                         "Repeated TCP/445 activity between hosts correlates\n"
                         "with the simulated propagation stage. However,\n"
                         "TCP/445 activity alone does NOT confirm WannaCry.\n"
                         "This correlation requires corroborating endpoint\n"
                         "and file system evidence."
                     ),
                     font=("Consolas", 9),
                     text_color=COLORS["text_warning"],
                     justify="left").pack(padx=10, pady=8)

    def _analyze(self):
        def _run():
            from forensics.network_analyzer import analyze_smb_traffic, get_all_traffic
            result = analyze_smb_traffic()
            traffic = get_all_traffic()
            self.after(0, lambda: self._show_results(result, traffic))

        threading.Thread(target=_run, daemon=True).start()

    def _show_results(self, result, traffic):
        self._all_traffic = traffic
        self._render_traffic(traffic)

        # Analysis text
        self.analysis_box.configure(state="normal")
        self.analysis_box.delete("1.0", "end")
        self.analysis_box.insert("end", "SMB TRAFFIC ANALYSIS\n")
        self.analysis_box.insert("end", "=" * 40 + "\n\n")
        self.analysis_box.insert("end", f"Total events:   {result['total_events']}\n")
        self.analysis_box.insert("end", f"SMB/445 events: {result['smb_events']}\n\n")
        self.analysis_box.insert("end", "SMB Sources:\n")
        for s in result.get("smb_sources", []):
            self.analysis_box.insert("end", f"  • {s}\n")
        self.analysis_box.insert("end", "\nSMB Destinations:\n")
        for d in result.get("smb_destinations", []):
            self.analysis_box.insert("end", f"  • {d}\n")
        self.analysis_box.insert("end", "\nFINDING:\n")
        self.analysis_box.insert("end", result.get("finding", ""))
        self.analysis_box.configure(state="disabled")
        self.app.log_event(f"Network analysis: {result['smb_events']} SMB events found", "info")

    def _apply_port_filter(self):
        port = self.port_filter.get().strip()
        if port:
            from forensics.network_analyzer import get_all_traffic
            filtered = get_all_traffic(port_filter=port)
            self._render_traffic(filtered)
        else:
            self._render_traffic(self._all_traffic)

    def _render_traffic(self, traffic):
        for w in self.traffic_frame.winfo_children():
            w.destroy()

        for i, ev in enumerate(traffic):
            bg = COLORS["bg_card"] if i % 2 == 0 else COLORS["bg_card2"]
            row = ctk.CTkFrame(self.traffic_frame, fg_color=bg)
            row.pack(fill="x", pady=1)

            port = ev.get("port", "")
            is_smb = port == 445
            clr = COLORS["compromised"] if is_smb else COLORS["text_primary"]

            ts = str(ev.get("event_ts", ""))[:19]
            for val, w in [(ts[:8], 100),
                           (ev.get("source_ip", ""), 130),
                           (ev.get("dest_ip", ""), 130),
                           (str(port), 55),
                           (ev.get("protocol", ""), 90),
                           (ev.get("event_type", "")[:18], 130)]:
                ctk.CTkLabel(row, text=str(val), font=("Courier New", 9),
                             text_color=clr, width=w, anchor="w").pack(
                    side="left", padx=3, pady=3)

    def refresh(self):
        pass
