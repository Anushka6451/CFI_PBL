"""
Evidence Explorer Page — WannaCry Forensic Lab
Browse, search, filter and inspect all collected forensic evidence.
"""

import tkinter as tk
import customtkinter as ctk
import threading
from gui.theme import COLORS, FONTS, BUTTON_STYLES
from gui.widgets import EvidenceTable, SectionFrame


class EvidencePage(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self.app = app
        self._selected_ev = None
        self._build_ui()

    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_darkest"],
                           corner_radius=0, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="🔍  EVIDENCE EXPLORER",
                     font=FONTS["heading"],
                     text_color=COLORS["accent_cyan"]).pack(side="left", padx=20, pady=14)
        self.count_lbl = ctk.CTkLabel(hdr, text="",
                                      font=("Consolas", 11),
                                      text_color=COLORS["accent_blue"])
        self.count_lbl.pack(side="right", padx=20)

        # ── Toolbar ───────────────────────────────────────────────────────────
        toolbar = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"],
                               corner_radius=0, height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        ctk.CTkButton(toolbar, text="📦  COLLECT EVIDENCE",
                      command=self._collect_evidence,
                      **BUTTON_STYLES["primary"],
                      width=180).pack(side="left", padx=12, pady=8)

        # Search
        ctk.CTkLabel(toolbar, text="Search:",
                     font=FONTS["small"],
                     text_color=COLORS["text_secondary"]).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_filters())
        self.search_entry = ctk.CTkEntry(toolbar, textvariable=self.search_var,
                                         width=160,
                                         fg_color=COLORS["bg_input"],
                                         border_color=COLORS["border"],
                                         text_color=COLORS["text_primary"],
                                         font=("Consolas", 11))
        self.search_entry.pack(side="left", padx=6)

        # Machine filter
        ctk.CTkLabel(toolbar, text="Machine:",
                     font=FONTS["small"],
                     text_color=COLORS["text_secondary"]).pack(side="left", padx=(10, 0))
        self.machine_filter = ctk.CTkComboBox(
            toolbar, values=["ALL", "PC-01", "PC-02", "PC-03"],
            command=lambda *_: self._apply_filters(),
            fg_color=COLORS["bg_input"], border_color=COLORS["border"],
            button_color=COLORS["accent_blue"],
            text_color=COLORS["text_primary"], font=("Consolas", 11), width=100)
        self.machine_filter.set("ALL")
        self.machine_filter.pack(side="left", padx=6)

        # Type filter
        ctk.CTkLabel(toolbar, text="Type:",
                     font=FONTS["small"],
                     text_color=COLORS["text_secondary"]).pack(side="left", padx=(10, 0))
        self.type_filter = ctk.CTkComboBox(
            toolbar,
            values=["ALL", "AFFECTED_FILE", "RANSOM_NOTE", "INFECTION_MARKER",
                    "ENDPOINT_LOG", "NETWORK_LOG", "DOCUMENT"],
            command=lambda *_: self._apply_filters(),
            fg_color=COLORS["bg_input"], border_color=COLORS["border"],
            button_color=COLORS["accent_blue"],
            text_color=COLORS["text_primary"], font=("Consolas", 11), width=160)
        self.type_filter.set("ALL")
        self.type_filter.pack(side="left", padx=6)

        # Navigation buttons
        ctk.CTkButton(toolbar, text="File Forensics ⟶",
                      command=lambda: self.app.show_page("file_forensics"),
                      **BUTTON_STYLES["secondary"],
                      width=140).pack(side="right", padx=6, pady=8)
        ctk.CTkButton(toolbar, text="Network ⟶",
                      command=lambda: self.app.show_page("network_forensics"),
                      **BUTTON_STYLES["secondary"],
                      width=110).pack(side="right", padx=4, pady=8)

        # ── Body ──────────────────────────────────────────────────────────────
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        # Evidence table
        self.ev_table = EvidenceTable(body, on_select=self._select_evidence)
        self.ev_table.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        # Detail panel
        detail = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                              corner_radius=10, border_color=COLORS["border"],
                              border_width=1)
        detail.grid(row=0, column=1, sticky="nsew")

        ctk.CTkLabel(detail, text="EVIDENCE DETAIL",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 6))

        self.detail_id = ctk.CTkLabel(detail, text="Select an evidence item",
                                      font=("Consolas", 12, "bold"),
                                      text_color=COLORS["accent_yellow"])
        self.detail_id.pack(pady=4)

        self.detail_frame = ctk.CTkScrollableFrame(detail, fg_color="transparent")
        self.detail_frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        # Preview
        ctk.CTkLabel(detail, text="CONTENT PREVIEW",
                     font=FONTS["small"],
                     text_color=COLORS["text_secondary"]).pack(pady=(4, 2))
        self.preview_box = ctk.CTkTextbox(detail,
                                          fg_color=COLORS["bg_darkest"],
                                          text_color=COLORS["text_primary"],
                                          font=("Courier New", 10),
                                          height=160)
        self.preview_box.pack(fill="x", padx=12, pady=(0, 12))

        # Integrity badge
        self.integrity_lbl = ctk.CTkLabel(detail, text="",
                                          font=("Consolas", 11, "bold"))
        self.integrity_lbl.pack(pady=(0, 12))

        self.status_lbl = ctk.CTkLabel(self, text="Click 'Collect Evidence' to begin investigation.",
                                       font=("Consolas", 11),
                                       text_color=COLORS["text_secondary"])
        self.status_lbl.pack(pady=4)

    def _collect_evidence(self):
        self.status_lbl.configure(text="Collecting evidence…",
                                  text_color=COLORS["text_warning"])
        self.update()

        def _run():
            from forensics.evidence_collector import collect_all_evidence
            collected = collect_all_evidence()
            self.after(0, lambda: self._evidence_collected(collected))

        threading.Thread(target=_run, daemon=True).start()

    def _evidence_collected(self, collected):
        self.status_lbl.configure(
            text=f"✓ Evidence collection complete — {len(collected)} items catalogued",
            text_color=COLORS["safe"])
        self.app.on_evidence_collected(collected)
        self._apply_filters()
        self.app.log_event(f"Evidence collected — {len(collected)} items with SHA-256 hashes", "success")
        self.app.mark_step(8, done=True)

    def _apply_filters(self, *_):
        from database import db_manager
        search = self.search_var.get().strip()
        machine = self.machine_filter.get()
        ev_type = self.type_filter.get()
        evidence = db_manager.get_evidence(search or None,
                                           machine if machine != "ALL" else None,
                                           ev_type if ev_type != "ALL" else None)
        self.ev_table.load_evidence(evidence)
        self.count_lbl.configure(text=f"{len(evidence)} items")

    def _select_evidence(self, ev):
        self._selected_ev = ev

        # Clear detail
        for w in self.detail_frame.winfo_children():
            w.destroy()

        self.detail_id.configure(text=f"Evidence: {ev.get('evidence_id', '')}")

        rows = [
            ("ID",          ev.get("evidence_id", "")),
            ("Type",        ev.get("evidence_type", "")),
            ("Machine",     ev.get("machine", "")),
            ("Filename",    ev.get("filename", "")),
            ("Size",        f"{ev.get('file_size', 0)} bytes"),
            ("Collected",   str(ev.get("collected_at", ""))[:19]),
            ("Integrity",   ev.get("integrity_status", "PENDING")),
        ]
        for label, val in rows:
            f = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
            f.pack(fill="x", pady=2)
            ctk.CTkLabel(f, text=label + ":",
                         font=("Consolas", 10),
                         text_color=COLORS["text_secondary"],
                         width=90, anchor="w").pack(side="left")
            ctk.CTkLabel(f, text=str(val),
                         font=("Consolas", 10, "bold"),
                         text_color=COLORS["text_primary"],
                         anchor="w", wraplength=200).pack(side="left", padx=4)

        # SHA-256
        sha = ev.get("sha256_acquisition", "")
        sha_frame = ctk.CTkFrame(self.detail_frame, fg_color=COLORS["bg_darkest"],
                                  corner_radius=4)
        sha_frame.pack(fill="x", pady=6)
        ctk.CTkLabel(sha_frame, text="SHA-256 (Acquisition):",
                     font=("Consolas", 9),
                     text_color=COLORS["text_secondary"]).pack(anchor="w", padx=8, pady=(4, 0))
        ctk.CTkLabel(sha_frame, text=sha[:32] + "\n" + sha[32:],
                     font=("Courier New", 9),
                     text_color=COLORS["accent_cyan"],
                     anchor="w", justify="left").pack(padx=8, pady=(0, 4))

        # Description
        ctk.CTkLabel(self.detail_frame, text=ev.get("description", ""),
                     font=("Consolas", 9),
                     text_color=COLORS["text_secondary"],
                     wraplength=260, justify="left").pack(pady=4)

        # Preview
        self.preview_box.configure(state="normal")
        self.preview_box.delete("1.0", "end")
        self.preview_box.insert("end", ev.get("content_preview", "")[:300])
        self.preview_box.configure(state="disabled")

        # Integrity
        status = ev.get("integrity_status", "PENDING")
        if status == "VERIFIED":
            self.integrity_lbl.configure(text="✅ INTEGRITY VERIFIED",
                                         text_color=COLORS["safe"])
        elif status == "MODIFIED":
            self.integrity_lbl.configure(text="⚠ INTEGRITY MODIFIED",
                                         text_color=COLORS["compromised"])
        else:
            self.integrity_lbl.configure(text="⏳ PENDING VERIFICATION",
                                         text_color=COLORS["text_secondary"])

    def refresh(self):
        self._apply_filters()
