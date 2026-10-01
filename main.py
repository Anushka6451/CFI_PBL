"""
WannaCry Forensic Investigation Lab — Main Application
Entry point and main window controller.

Run:  python main.py
"""

import sys
import os

# Ensure project root is on the path for all imports
sys.path.insert(0, os.path.dirname(__file__))

import tkinter as tk
import customtkinter as ctk
from gui.theme import COLORS, FONTS, BUTTON_STYLES
from gui.widgets import EventConsole

# ── CustomTkinter global appearance ──────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class WannaCryForensicLab(ctk.CTk):
    """Main application window."""

    # Page registry — (display_name, page_class_import_path)
    PAGE_REGISTRY = [
        ("dashboard",         "gui.page_dashboard",         "DashboardPage"),
        ("network",           "gui.page_network",           "NetworkPage"),
        ("simulation",        "gui.page_simulation",        "SimulationPage"),
        ("evidence",          "gui.page_evidence",          "EvidencePage"),
        ("file_forensics",    "gui.page_file_forensics",    "FileForensicsPage"),
        ("network_forensics", "gui.page_network_forensics", "NetworkForensicsPage"),
        ("hash",              "gui.page_hash",              "HashPage"),
        ("timeline",          "gui.page_timeline",          "TimelinePage"),
        ("reconstruction",    "gui.page_reconstruction",    "ReconstructionPage"),
        ("findings",          "gui.page_findings",          "FindingsPage"),
        ("containment",       "gui.page_containment",       "ContainmentPage"),
        ("prevention",        "gui.page_prevention",        "PreventionPage"),
        ("case_analysis",     "gui.page_case_analysis",     "CaseAnalysisPage"),
    ]

    NAV_ITEMS = [
        ("🏠", "Dashboard",       "dashboard"),
        ("🏥", "Hospital Network", "network"),
        ("💀", "Simulation",      "simulation"),
        ("🔍", "Evidence",        "evidence"),
        ("📁", "File Forensics",  "file_forensics"),
        ("🌐", "Net Forensics",   "network_forensics"),
        ("🔐", "Hash Verify",     "hash"),
        ("📅", "Timeline",        "timeline"),
        ("🗺", "Reconstruction",  "reconstruction"),
        ("🎯", "Findings",        "findings"),
        ("🔒", "Containment",     "containment"),
        ("🛡", "Prevention",      "prevention"),
        ("📋", "Case Analysis",   "case_analysis"),
    ]

    def __init__(self):
        super().__init__()
        self.title("WannaCry Forensic Investigation Lab — Cyber Terrorism Incident Simulation")
        self.geometry("1440x860")
        self.minsize(1200, 720)
        self.configure(fg_color=COLORS["bg_darkest"])

        # App state
        self._current_page = None
        self._pages = {}
        self._nav_buttons = {}

        # Initialize database
        from database import db_manager
        db_manager.initialize_database()

        self._build_layout()
        self._build_nav()
        self._load_pages()
        self.show_page("dashboard")

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_layout(self):
        """Build the fixed 3-column layout: sidebar | main | event log."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0)  # nav sidebar
        self.grid_columnconfigure(1, weight=1)  # main content
        self.grid_columnconfigure(2, weight=0)  # event log

        # Sidebar
        self.sidebar = ctk.CTkFrame(self,
                                    fg_color=COLORS["bg_darkest"],
                                    width=190,
                                    corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # Main content area
        self.content = ctk.CTkFrame(self,
                                    fg_color=COLORS["bg_dark"],
                                    corner_radius=0)
        self.content.grid(row=0, column=1, sticky="nsew")

        # Right event log panel
        self.log_panel = ctk.CTkFrame(self,
                                      fg_color=COLORS["bg_darkest"],
                                      width=260,
                                      corner_radius=0)
        self.log_panel.grid(row=0, column=2, sticky="nsew")
        self.log_panel.grid_propagate(False)
        self._build_log_panel()

    def _build_nav(self):
        """Build the left navigation sidebar."""
        # Logo / title
        logo_frame = ctk.CTkFrame(self.sidebar,
                                  fg_color=COLORS["bg_panel"],
                                  corner_radius=0, height=80)
        logo_frame.pack(fill="x")
        logo_frame.pack_propagate(False)

        ctk.CTkLabel(logo_frame,
                     text="⚠",
                     font=("Consolas", 28, "bold"),
                     text_color=COLORS["compromised"]).pack(pady=(12, 0))
        ctk.CTkLabel(logo_frame,
                     text="FORENSIC LAB",
                     font=("Consolas", 10, "bold"),
                     text_color=COLORS["accent_blue"]).pack()

        # Navigation buttons
        nav_scroll = ctk.CTkScrollableFrame(self.sidebar,
                                            fg_color="transparent",
                                            scrollbar_button_color=COLORS["bg_panel"])
        nav_scroll.pack(fill="both", expand=True, pady=8)

        for emoji, label, page_key in self.NAV_ITEMS:
            btn = ctk.CTkButton(
                nav_scroll,
                text=f" {emoji}  {label}",
                command=lambda k=page_key: self.show_page(k),
                fg_color="transparent",
                hover_color=COLORS["bg_hover"],
                text_color=COLORS["text_secondary"],
                font=("Consolas", 11),
                anchor="w",
                corner_radius=6,
                height=36,
            )
            btn.pack(fill="x", padx=8, pady=2)
            self._nav_buttons[page_key] = btn

        # Bottom: version / safety notice
        bottom = ctk.CTkFrame(self.sidebar,
                              fg_color=COLORS["bg_panel"],
                              corner_radius=0)
        bottom.pack(fill="x", side="bottom")
        ctk.CTkLabel(bottom,
                     text="EDUCATIONAL SANDBOX\nNO REAL MALWARE\nv1.0.0",
                     font=("Consolas", 8),
                     text_color=COLORS["text_dim"],
                     justify="center").pack(pady=8)

    def _build_log_panel(self):
        """Build the persistent right-side event log."""
        ctk.CTkLabel(self.log_panel,
                     text="⚡ EVENT LOG",
                     font=("Consolas", 11, "bold"),
                     text_color=COLORS["accent_blue"]).pack(pady=(12, 4))

        self.global_log = EventConsole(self.log_panel)
        self.global_log.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.global_log.append("WannaCry Forensic Lab started.", "success")
        self.global_log.append("─" * 28, "dim")
        self.global_log.append("Begin by setting up the", "info")
        self.global_log.append("hospital environment.", "info")

    # ── Page management ───────────────────────────────────────────────────────

    def _load_pages(self):
        """Lazy-import and instantiate all pages."""
        import importlib
        for page_key, module_path, class_name in self.PAGE_REGISTRY:
            try:
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name)
                page = cls(self.content, app=self)
                page.place(relx=0, rely=0, relwidth=1, relheight=1)
                self._pages[page_key] = page
            except Exception as e:
                print(f"[WARN] Could not load page {page_key}: {e}")

    def show_page(self, page_key: str):
        """Switch to a different page."""
        # Hide all
        for page in self._pages.values():
            page.place_forget()

        # Show target
        if page_key in self._pages:
            self._pages[page_key].place(relx=0, rely=0, relwidth=1, relheight=1)
            try:
                self._pages[page_key].refresh()
            except Exception:
                pass
            self._current_page = page_key

        # Update nav highlight
        for key, btn in self._nav_buttons.items():
            if key == page_key:
                btn.configure(fg_color=COLORS["bg_hover"],
                              text_color=COLORS["accent_blue"])
            else:
                btn.configure(fg_color="transparent",
                              text_color=COLORS["text_secondary"])

    # ── Global event callbacks ─────────────────────────────────────────────────

    def log_event(self, message: str, tag: str = "info"):
        """Append a message to the persistent event log panel."""
        self.global_log.append(f"▸ {message}", tag)

    def on_environment_ready(self):
        self.mark_step(0, done=True)
        self.mark_step(1, done=False)

    def on_baseline_captured(self, records):
        self.mark_step(1, done=True)
        self.mark_step(2, done=False)

    def on_simulation_complete(self):
        self.mark_step(7, done=True)

    def on_evidence_collected(self, collected):
        pass

    def on_machine_state_change(self, pc_id: str, state: str):
        """Propagate machine state change to all pages that show machine cards."""
        for page_key in ("network", "simulation", "containment"):
            page = self._pages.get(page_key)
            if page and hasattr(page, "update_machine_state"):
                try:
                    page.update_machine_state(pc_id, state)
                except Exception:
                    pass

    def mark_step(self, step_idx: int, done: bool = True):
        """Mark a workflow step in the dashboard."""
        dash = self._pages.get("dashboard")
        if dash:
            if done:
                dash.mark_step_done(step_idx)
            else:
                dash.mark_step_active(step_idx)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    app = WannaCryForensicLab()
    app.mainloop()


if __name__ == "__main__":
    main()
