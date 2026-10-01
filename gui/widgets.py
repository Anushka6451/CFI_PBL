"""
Widgets — Reusable GUI Components for WannaCry Forensic Lab
"""

import tkinter as tk
import customtkinter as ctk
from gui.theme import COLORS, FONTS, STATUS_COLORS, STATUS_EMOJI


def make_section_header(parent, text, color=None):
    color = color or COLORS["accent_blue"]
    frame = ctk.CTkFrame(parent, fg_color=COLORS["bg_panel"],
                         border_color=color, border_width=1, corner_radius=6)
    lbl = ctk.CTkLabel(frame, text=f"  {text}  ",
                       font=FONTS["heading"],
                       text_color=color,
                       fg_color=COLORS["bg_panel"])
    lbl.pack(padx=12, pady=8)
    return frame


def make_status_badge(parent, text, state="SAFE"):
    color = STATUS_COLORS.get(state, COLORS["text_secondary"])
    emoji = STATUS_EMOJI.get(state, "⚪")
    lbl = ctk.CTkLabel(parent,
                       text=f"{emoji} {text}",
                       font=FONTS["label"],
                       text_color=color,
                       fg_color=COLORS["bg_card"],
                       corner_radius=4)
    return lbl


def make_info_row(parent, label, value, label_color=None, value_color=None):
    """A key-value row for metadata display."""
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    ctk.CTkLabel(frame, text=label + ":",
                 font=FONTS["small"],
                 text_color=label_color or COLORS["text_secondary"],
                 width=160, anchor="w").pack(side="left")
    ctk.CTkLabel(frame, text=str(value),
                 font=FONTS["mono_sm"],
                 text_color=value_color or COLORS["text_primary"],
                 anchor="w").pack(side="left", padx=(4, 0))
    return frame


class EventConsole(ctk.CTkTextbox):
    """Scrollable event log / console widget."""
    def __init__(self, parent, **kwargs):
        super().__init__(
            parent,
            fg_color=COLORS["bg_darkest"],
            text_color=COLORS["text_primary"],
            font=("Courier New", 11),
            state="disabled",
            **kwargs
        )
        self.tag_config("critical", foreground=COLORS["sev_critical"])
        self.tag_config("high",     foreground=COLORS["sev_high"])
        self.tag_config("medium",   foreground=COLORS["sev_medium"])
        self.tag_config("info",     foreground=COLORS["sev_info"])
        self.tag_config("success",  foreground=COLORS["sev_success"])
        self.tag_config("dim",      foreground=COLORS["text_dim"])
        self.tag_config("header",   foreground=COLORS["text_header"])

    def append(self, text, tag="info"):
        self.configure(state="normal")
        self.insert("end", text + "\n", tag)
        self.see("end")
        self.configure(state="disabled")

    def clear(self):
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.configure(state="disabled")


class MachineCard(ctk.CTkFrame):
    """Visual machine status card for the network diagram."""
    def __init__(self, parent, pc_id, name, ip, **kwargs):
        super().__init__(parent, corner_radius=10,
                         border_width=2, **kwargs)
        self.pc_id = pc_id
        self.machine_name = name
        self._state = "SAFE"
        self._setup_ui(name, ip)
        self.set_state("SAFE")

    def _setup_ui(self, name, ip):
        self.configure(fg_color=COLORS["bg_card"], border_color=COLORS["border"])

        self.name_lbl = ctk.CTkLabel(self, text=name,
                                     font=("Consolas", 12, "bold"),
                                     text_color=COLORS["text_header"])
        self.name_lbl.pack(pady=(10, 2))

        self.ip_lbl = ctk.CTkLabel(self, text=ip,
                                   font=("Courier New", 10),
                                   text_color=COLORS["text_secondary"])
        self.ip_lbl.pack()

        self.status_lbl = ctk.CTkLabel(self, text="",
                                       font=("Consolas", 12, "bold"))
        self.status_lbl.pack(pady=(6, 10))

    def set_state(self, state: str):
        self._state = state
        color = STATUS_COLORS.get(state, COLORS["text_secondary"])
        emoji = STATUS_EMOJI.get(state, "⚪")
        self.status_lbl.configure(text=f"{emoji} {state}", text_color=color)
        self.configure(border_color=color)
        if state == "COMPROMISED":
            self.configure(fg_color="#1A0A0A")
        elif state == "SAFE":
            self.configure(fg_color=COLORS["bg_card"])
        elif state == "ISOLATED":
            self.configure(fg_color="#1A1500")
        elif state in ("RECOVERED", "PROTECTED"):
            self.configure(fg_color="#0A1A0A")
        else:
            self.configure(fg_color=COLORS["bg_card2"])

    def get_state(self):
        return self._state


class EvidenceTable(ctk.CTkScrollableFrame):
    """Scrollable evidence table with selectable rows."""
    COLS = [
        ("ID",       80),
        ("Time",    130),
        ("Machine",  80),
        ("Type",    140),
        ("Filename", 220),
        ("SHA-256",  160),
    ]

    def __init__(self, parent, on_select=None, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_darkest"], **kwargs)
        self.on_select = on_select
        self.row_frames = []
        self._build_header()

    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"])
        hdr.pack(fill="x", pady=(0, 2))
        for col, width in self.COLS:
            ctk.CTkLabel(hdr, text=col, font=("Consolas", 11, "bold"),
                         text_color=COLORS["accent_blue"],
                         width=width, anchor="w").pack(side="left", padx=4)

    def load_evidence(self, evidence_list):
        # Clear old rows
        for f in self.row_frames:
            f.destroy()
        self.row_frames.clear()

        for ev in evidence_list:
            self._add_row(ev)

    def _add_row(self, ev):
        bg = COLORS["bg_card"] if len(self.row_frames) % 2 == 0 else COLORS["bg_card2"]
        row = ctk.CTkFrame(self, fg_color=bg, corner_radius=4)
        row.pack(fill="x", pady=1)

        # Determine row color based on type
        type_colors = {
            "RANSOM_NOTE":      COLORS["compromised"],
            "INFECTION_MARKER": COLORS["affected"],
            "AFFECTED_FILE":    COLORS["accent_orange"],
            "ENDPOINT_LOG":     COLORS["accent_blue"],
            "NETWORK_LOG":      COLORS["accent_cyan"],
            "DOCUMENT":         COLORS["text_secondary"],
        }
        tc = type_colors.get(ev.get("evidence_type", ""), COLORS["text_primary"])

        ts = ev.get("collected_at", "")[:19].replace("T", " ")
        sha_short = (ev.get("sha256_acquisition", "") or "")[:16] + "…"

        vals = [
            ev.get("evidence_id", ""),
            ts,
            ev.get("machine", ""),
            ev.get("evidence_type", ""),
            ev.get("filename", ""),
            sha_short,
        ]
        for i, (val, (_, width)) in enumerate(zip(vals, self.COLS)):
            clr = tc if i in (0, 3) else COLORS["text_primary"]
            ctk.CTkLabel(row, text=str(val), font=("Consolas", 10),
                         text_color=clr, width=width, anchor="w").pack(
                side="left", padx=4)

        if self.on_select:
            row.bind("<Button-1>", lambda e, ev=ev: self.on_select(ev))
            for child in row.winfo_children():
                child.bind("<Button-1>", lambda e, ev=ev: self.on_select(ev))

        self.row_frames.append(row)


class ProgressStep(ctk.CTkFrame):
    """A workflow step indicator."""
    def __init__(self, parent, step_num, label, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.step_num = step_num
        self.active = False

        self.circle = ctk.CTkLabel(self, text=str(step_num),
                                   width=32, height=32,
                                   fg_color=COLORS["bg_panel"],
                                   corner_radius=16,
                                   font=("Consolas", 11, "bold"),
                                   text_color=COLORS["text_dim"])
        self.circle.pack(side="left", padx=(0, 8))
        self.label_lbl = ctk.CTkLabel(self, text=label,
                                      font=("Consolas", 11),
                                      text_color=COLORS["text_dim"],
                                      anchor="w")
        self.label_lbl.pack(side="left")

    def set_active(self, done=False):
        if done:
            self.circle.configure(fg_color=COLORS["safe"], text_color="#000000",
                                  text="✓")
            self.label_lbl.configure(text_color=COLORS["safe"])
        else:
            self.circle.configure(fg_color=COLORS["accent_blue"],
                                  text_color="#FFFFFF",
                                  text=str(self.step_num))
            self.label_lbl.configure(text_color=COLORS["accent_blue"])


class SectionFrame(ctk.CTkFrame):
    """A styled content section frame."""
    def __init__(self, parent, title="", border_color=None, **kwargs):
        bc = border_color or COLORS["border"]
        super().__init__(parent, fg_color=COLORS["bg_card"],
                         border_color=bc, border_width=1,
                         corner_radius=8, **kwargs)
        if title:
            ctk.CTkLabel(self, text=f" {title} ",
                         font=FONTS["subhead"],
                         text_color=bc,
                         fg_color=COLORS["bg_card"],
                         corner_radius=4).pack(anchor="nw", padx=12, pady=(10, 6))
