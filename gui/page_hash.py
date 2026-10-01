"""
Hash Verification Page — WannaCry Forensic Lab
"""
import tkinter as tk
import customtkinter as ctk
import threading
from gui.theme import COLORS, FONTS, BUTTON_STYLES


class HashPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_darkest"],
                           corner_radius=0, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="🔐  HASH VERIFICATION — EVIDENCE INTEGRITY",
                     font=FONTS["heading"],
                     text_color=COLORS["accent_cyan"]).pack(side="left", padx=20, pady=14)

        toolbar = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"],
                               corner_radius=0, height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        ctk.CTkButton(toolbar, text="🔍  VERIFY ALL EVIDENCE INTEGRITY",
                      command=self._verify_all,
                      **BUTTON_STYLES["primary"],
                      width=260).pack(side="left", padx=12, pady=8)
        ctk.CTkButton(toolbar, text="⟶  Timeline",
                      command=lambda: self.app.show_page("timeline"),
                      **BUTTON_STYLES["secondary"],
                      width=110).pack(side="right", padx=12, pady=8)

        self.summary_lbl = ctk.CTkLabel(toolbar, text="",
                                        font=("Consolas", 11, "bold"),
                                        text_color=COLORS["safe"])
        self.summary_lbl.pack(side="left", padx=12)

        # Results table
        body = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"],
                            corner_radius=10, border_color=COLORS["border"],
                            border_width=1)
        body.pack(fill="both", expand=True, padx=16, pady=12)

        ctk.CTkLabel(body,
                     text="Evidence Integrity Verification — SHA-256 Hash Comparison",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 4))

        ctk.CTkLabel(body,
                     text=(
                         "Forensic principle: The SHA-256 hash of evidence must match\n"
                         "the acquisition hash to confirm integrity (no post-collection modification)."
                     ),
                     font=("Consolas", 10),
                     text_color=COLORS["text_secondary"],
                     justify="left").pack(padx=20, pady=(0, 10))

        # Table header
        hdr_row = ctk.CTkFrame(body, fg_color=COLORS["bg_darkest"])
        hdr_row.pack(fill="x", padx=12)
        for col, w in [("Evidence ID", 100), ("Machine", 80), ("Filename", 230),
                        ("Acquisition Hash", 200), ("Status", 100)]:
            ctk.CTkLabel(hdr_row, text=col, font=("Consolas", 11, "bold"),
                         text_color=COLORS["accent_blue"],
                         width=w, anchor="w").pack(side="left", padx=4, pady=6)

        self.results_frame = ctk.CTkScrollableFrame(body, fg_color=COLORS["bg_darkest"])
        self.results_frame.pack(fill="both", expand=True, padx=12, pady=(2, 12))

        self.status_lbl = ctk.CTkLabel(body, text="",
                                       font=("Consolas", 11),
                                       text_color=COLORS["text_secondary"])
        self.status_lbl.pack(pady=(0, 8))

    def _verify_all(self):
        self.status_lbl.configure(text="Verifying SHA-256 hashes…",
                                  text_color=COLORS["text_warning"])
        self.update()

        def _run():
            from forensics.hashing import verify_all_evidence
            results = verify_all_evidence()
            self.after(0, lambda: self._show_results(results))

        threading.Thread(target=_run, daemon=True).start()

    def _show_results(self, results):
        for w in self.results_frame.winfo_children():
            w.destroy()

        verified = sum(1 for r in results if r["status"] == "VERIFIED")
        modified = sum(1 for r in results if r["status"] == "MODIFIED")
        missing = sum(1 for r in results if r["status"] == "FILE_MISSING")

        for i, r in enumerate(results):
            bg = COLORS["bg_card"] if i % 2 == 0 else COLORS["bg_card2"]
            row = ctk.CTkFrame(self.results_frame, fg_color=bg)
            row.pack(fill="x", pady=1)

            status = r["status"]
            if status == "VERIFIED":
                s_text, s_color = "✓ VERIFIED", COLORS["safe"]
            elif status == "MODIFIED":
                s_text, s_color = "⚠ MODIFIED", COLORS["compromised"]
            else:
                s_text, s_color = "? MISSING", COLORS["accent_yellow"]

            sha_short = (r.get("original_hash") or "")[:20] + "…"
            vals = [
                (r["evidence_id"], 100, COLORS["accent_cyan"]),
                (r.get("machine", ""), 80, COLORS["text_primary"]),
                (r.get("filename", ""), 230, COLORS["text_primary"]),
                (sha_short, 200, COLORS["text_secondary"]),
                (s_text, 100, s_color),
            ]
            for text, width, color in vals:
                ctk.CTkLabel(row, text=str(text),
                             font=("Consolas", 10),
                             text_color=color,
                             width=width, anchor="w").pack(side="left", padx=4, pady=4)

        summary = f"✅ {verified} VERIFIED  |  "
        if modified:
            summary += f"⚠ {modified} MODIFIED  |  "
        if missing:
            summary += f"? {missing} MISSING"
        self.summary_lbl.configure(
            text=summary,
            text_color=COLORS["safe"] if not modified and not missing else COLORS["compromised"]
        )
        self.status_lbl.configure(
            text=f"Verification complete — {len(results)} evidence items checked",
            text_color=COLORS["safe"]
        )
        self.app.mark_step(10, done=True)
        self.app.log_event(f"Hash verification: {verified} verified, {modified} modified", "success")

    def refresh(self):
        pass
