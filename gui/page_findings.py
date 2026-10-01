"""
Findings Page — WannaCry Forensic Lab
Summary of investigation findings after evidence collection.
"""
import customtkinter as ctk
from gui.theme import COLORS, FONTS, BUTTON_STYLES


class FindingsPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_darkest"],
                           corner_radius=0, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="🎯  INVESTIGATION FINDINGS",
                     font=FONTS["heading"],
                     text_color=COLORS["accent_cyan"]).pack(side="left", padx=20, pady=14)

        toolbar = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"],
                               corner_radius=0, height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)
        ctk.CTkButton(toolbar, text="🔄  REFRESH FINDINGS",
                      command=self.refresh,
                      **BUTTON_STYLES["primary"], width=180).pack(
            side="left", padx=12, pady=8)
        ctk.CTkButton(toolbar, text="⟶  Containment",
                      command=lambda: self.app.show_page("containment"),
                      **BUTTON_STYLES["warning"], width=140).pack(
            side="right", padx=12, pady=8)

        body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)

        self.content_frame = body
        self._render()

    def _render(self):
        for w in self.content_frame.winfo_children():
            w.destroy()

        try:
            from forensics.timeline import build_investigation_summary
            s = build_investigation_summary()
        except Exception:
            s = {}

        # Alert banner
        alert = ctk.CTkFrame(self.content_frame,
                             fg_color="#1A0000",
                             border_color=COLORS["compromised"],
                             border_width=2, corner_radius=8)
        alert.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(alert, text="🚨  CYBER INCIDENT DETECTED — INVESTIGATION FINDINGS",
                     font=("Consolas", 14, "bold"),
                     text_color=COLORS["compromised"]).pack(pady=12)

        # Stats row
        stats_row = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        stats_row.pack(fill="x", pady=(0, 12))

        stat_items = [
            ("Compromised Hosts", str(s.get("affected_hosts", 0)), COLORS["compromised"]),
            ("Affected Files", str(s.get("total_affected_files", 0)), COLORS["affected"]),
            ("SMB Events", str(s.get("smb_event_count", 0)), COLORS["accent_orange"]),
            ("Ransom Notes", str(s.get("ransom_note_count", 0)), COLORS["accent_yellow"]),
            ("Evidence Items", str(s.get("evidence_count", 0)), COLORS["accent_blue"]),
        ]
        for label, value, color in stat_items:
            card = ctk.CTkFrame(stats_row,
                                fg_color=COLORS["bg_card"],
                                border_color=color, border_width=1,
                                corner_radius=8)
            card.pack(side="left", fill="x", expand=True, padx=4)
            ctk.CTkLabel(card, text=value,
                         font=("Consolas", 28, "bold"),
                         text_color=color).pack(pady=(10, 0))
            ctk.CTkLabel(card, text=label,
                         font=("Consolas", 9),
                         text_color=COLORS["text_secondary"]).pack(pady=(0, 10))

        # Detail sections
        sections = [
            ("INITIAL AFFECTED HOST", s.get("initial_host", "—"), COLORS["compromised"]),
            ("PRIMARY FILE INDICATOR", s.get("primary_file_indicator", "—"),
             COLORS["affected"]),
            ("NETWORK INDICATOR", s.get("network_indicator", "—"), COLORS["accent_orange"]),
            ("RANSOMWARE INDICATOR", s.get("ransomware_indicator", "—"),
             COLORS["accent_yellow"]),
        ]
        row2 = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        row2.pack(fill="x", pady=(0, 12))
        for label, value, color in sections:
            card = ctk.CTkFrame(row2, fg_color=COLORS["bg_card"],
                                border_color=color, border_width=1,
                                corner_radius=8)
            card.pack(side="left", fill="x", expand=True, padx=4)
            ctk.CTkLabel(card, text=label,
                         font=("Consolas", 9, "bold"),
                         text_color=color).pack(pady=(8, 2))
            ctk.CTkLabel(card, text=value,
                         font=("Consolas", 10),
                         text_color=COLORS["text_primary"],
                         wraplength=220).pack(pady=(0, 8))

        # Attack sequence
        seq_frame = ctk.CTkFrame(self.content_frame, fg_color=COLORS["bg_panel"],
                                 border_color=COLORS["border"],
                                 border_width=1, corner_radius=8)
        seq_frame.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(seq_frame, text="ATTACK SEQUENCE",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(12, 6))
        for i, step in enumerate(s.get("attack_sequence", [])):
            arrow = "→" if i > 0 else "▶"
            ctk.CTkLabel(seq_frame, text=f"  {arrow}  {step}",
                         font=("Consolas", 10),
                         text_color=COLORS["text_primary"],
                         anchor="w").pack(fill="x", padx=20, pady=2)
        ctk.CTkLabel(seq_frame, text="", height=8).pack()

        # Attribution
        attr_frame = ctk.CTkFrame(self.content_frame, fg_color=COLORS["bg_card"],
                                  border_color=COLORS["accent_yellow"],
                                  border_width=1, corner_radius=8)
        attr_frame.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(attr_frame, text="ATTRIBUTION",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_yellow"]).pack(pady=(12, 4))
        ctk.CTkLabel(attr_frame, text=s.get("attribution", "—"),
                     font=("Consolas", 9),
                     text_color=COLORS["text_secondary"],
                     wraplength=800, justify="left").pack(padx=20, pady=(0, 12))

    def refresh(self):
        self._render()
