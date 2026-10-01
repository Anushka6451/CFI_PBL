"""
File Forensics Page — WannaCry Forensic Lab
Before/after comparison of all files impacted by the simulation.
"""
import tkinter as tk
import customtkinter as ctk
import threading
from gui.theme import COLORS, FONTS, BUTTON_STYLES


class FileForensicsPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_darkest"],
                           corner_radius=0, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="📁  FILE FORENSICS — BEFORE / AFTER ANALYSIS",
                     font=FONTS["heading"],
                     text_color=COLORS["accent_cyan"]).pack(side="left", padx=20, pady=14)

        toolbar = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"],
                               corner_radius=0, height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        ctk.CTkButton(toolbar, text="🔎  ANALYZE FILE CHANGES",
                      command=self._analyze,
                      **BUTTON_STYLES["primary"], width=220).pack(
            side="left", padx=12, pady=8)

        # Machine filter
        ctk.CTkLabel(toolbar, text="Machine:",
                     font=FONTS["small"],
                     text_color=COLORS["text_secondary"]).pack(side="left", padx=(12, 0))
        self.pc_filter = ctk.CTkComboBox(
            toolbar, values=["ALL", "PC-01", "PC-02", "PC-03"],
            command=lambda *_: self._apply_filter(),
            fg_color=COLORS["bg_input"], border_color=COLORS["border"],
            button_color=COLORS["accent_blue"],
            text_color=COLORS["text_primary"], font=("Consolas", 11), width=100)
        self.pc_filter.set("ALL")
        self.pc_filter.pack(side="left", padx=6)

        ctk.CTkButton(toolbar, text="⟶  Network Forensics",
                      command=lambda: self.app.show_page("network_forensics"),
                      **BUTTON_STYLES["secondary"], width=160).pack(
            side="right", padx=12, pady=8)

        self.finding_lbl = ctk.CTkLabel(toolbar, text="",
                                        font=("Consolas", 10),
                                        text_color=COLORS["text_secondary"],
                                        wraplength=600)
        self.finding_lbl.pack(side="left", padx=12)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # BEFORE panel
        before_frame = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                                    corner_radius=10,
                                    border_color=COLORS["safe"],
                                    border_width=1)
        before_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        ctk.CTkLabel(before_frame, text="BEFORE ATTACK (Baseline)",
                     font=FONTS["subhead"],
                     text_color=COLORS["safe"]).pack(pady=(14, 6))

        # Header row
        bh = ctk.CTkFrame(before_frame, fg_color=COLORS["bg_darkest"])
        bh.pack(fill="x", padx=8)
        for col, w in [("Machine", 70), ("Filename", 200), ("Size", 60), ("SHA-256", 130)]:
            ctk.CTkLabel(bh, text=col, font=("Consolas", 10, "bold"),
                         text_color=COLORS["safe"], width=w, anchor="w").pack(
                side="left", padx=4, pady=4)

        self.before_frame = ctk.CTkScrollableFrame(before_frame,
                                                    fg_color=COLORS["bg_darkest"])
        self.before_frame.pack(fill="both", expand=True, padx=8, pady=(2, 12))

        # AFTER panel
        after_frame = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                                   corner_radius=10,
                                   border_color=COLORS["compromised"],
                                   border_width=1)
        after_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 0))

        ctk.CTkLabel(after_frame, text="AFTER ATTACK (Current State)",
                     font=FONTS["subhead"],
                     text_color=COLORS["compromised"]).pack(pady=(14, 6))

        ah = ctk.CTkFrame(after_frame, fg_color=COLORS["bg_darkest"])
        ah.pack(fill="x", padx=8)
        for col, w in [("Machine", 70), ("Filename", 200), ("Status", 90), ("Impact Time", 130)]:
            ctk.CTkLabel(ah, text=col, font=("Consolas", 10, "bold"),
                         text_color=COLORS["compromised"], width=w, anchor="w").pack(
                side="left", padx=4, pady=4)

        self.after_frame = ctk.CTkScrollableFrame(after_frame,
                                                   fg_color=COLORS["bg_darkest"])
        self.after_frame.pack(fill="both", expand=True, padx=8, pady=(2, 12))

        self._all_data = []

    def _analyze(self):
        def _run():
            from forensics.file_analyzer import analyze_file_changes
            result = analyze_file_changes()
            self.after(0, lambda: self._show_results(result))

        threading.Thread(target=_run, daemon=True).start()

    def _show_results(self, result):
        self._all_data = result.get("comparison", [])
        self.finding_lbl.configure(
            text=result.get("finding", ""),
            text_color=COLORS["text_secondary"])
        self._apply_filter()
        self.app.mark_step(9, done=True)
        self.app.log_event(
            f"File analysis: {result['affected_count']}/{result['total_files']} files affected",
            "info")

    def _apply_filter(self, *_):
        pc = self.pc_filter.get()
        data = self._all_data
        if pc != "ALL":
            data = [d for d in data if d["machine"] == pc]

        # Before panel
        for w in self.before_frame.winfo_children():
            w.destroy()
        for i, d in enumerate(data):
            bg = COLORS["bg_card"] if i % 2 == 0 else COLORS["bg_card2"]
            row = ctk.CTkFrame(self.before_frame, fg_color=bg)
            row.pack(fill="x", pady=1)
            sha_s = (d.get("original_sha256") or "")[:12] + "…"
            for val, w in [(d["machine"], 70), (d["original_name"], 200),
                           (str(d.get("size_before", 0)) + "B", 60), (sha_s, 130)]:
                ctk.CTkLabel(row, text=str(val),
                             font=("Consolas", 9), text_color=COLORS["safe"],
                             width=w, anchor="w").pack(side="left", padx=4, pady=3)

        # After panel
        for w in self.after_frame.winfo_children():
            w.destroy()
        for i, d in enumerate(data):
            bg = COLORS["bg_card"] if i % 2 == 0 else COLORS["bg_card2"]
            row = ctk.CTkFrame(self.after_frame, fg_color=bg)
            row.pack(fill="x", pady=1)

            if d["status"] == "AFFECTED":
                name_color = COLORS["compromised"]
                status_color = COLORS["compromised"]
                status_text = "🔴 AFFECTED"
            else:
                name_color = COLORS["text_primary"]
                status_color = COLORS["safe"]
                status_text = "🟢 CLEAN"

            ts = (d.get("impact_ts") or "—")[:19]
            for val, w, clr in [(d["machine"], 70, COLORS["text_primary"]),
                                 (d["affected_name"], 200, name_color),
                                 (status_text, 90, status_color),
                                 (ts, 130, COLORS["text_secondary"])]:
                ctk.CTkLabel(row, text=str(val),
                             font=("Consolas", 9), text_color=clr,
                             width=w, anchor="w").pack(side="left", padx=4, pady=3)

    def refresh(self):
        pass
