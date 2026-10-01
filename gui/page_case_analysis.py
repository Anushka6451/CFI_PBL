"""
Case Analysis & Findings Page — WannaCry Forensic Lab
Final structured forensic case analysis with all 12 sections.
"""
import tkinter as tk
import customtkinter as ctk
import threading
import json
import csv
from datetime import datetime
from pathlib import Path
from gui.theme import COLORS, FONTS, BUTTON_STYLES


class CaseAnalysisPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_dark"], **kwargs)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_darkest"],
                           corner_radius=0, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="📋  FORENSIC CASE ANALYSIS REPORT",
                     font=FONTS["heading"],
                     text_color=COLORS["accent_cyan"]).pack(side="left", padx=20, pady=14)

        toolbar = ctk.CTkFrame(self, fg_color=COLORS["bg_panel"],
                               corner_radius=0, height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        ctk.CTkButton(toolbar, text="🔄  GENERATE ANALYSIS",
                      command=self._generate,
                      **BUTTON_STYLES["primary"], width=200).pack(
            side="left", padx=12, pady=8)
        ctk.CTkButton(toolbar, text="💾  EXPORT REPORT",
                      command=self._export,
                      **BUTTON_STYLES["secondary"], width=160).pack(
            side="left", padx=4, pady=8)

        self.export_lbl = ctk.CTkLabel(toolbar, text="",
                                       font=("Consolas", 10),
                                       text_color=COLORS["safe"])
        self.export_lbl.pack(side="left", padx=12)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        # Section nav (left)
        nav = ctk.CTkFrame(body, fg_color=COLORS["bg_panel"],
                           corner_radius=10, border_color=COLORS["border"],
                           border_width=1)
        nav.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ctk.CTkLabel(nav, text="CASE SECTIONS",
                     font=FONTS["subhead"],
                     text_color=COLORS["accent_blue"]).pack(pady=(14, 8))

        self._sections = [
            "1. Incident Description",
            "2. Evidence Identified",
            "3. Evidence Integrity",
            "4. File-System Findings",
            "5. Network Findings",
            "6. Attack Timeline",
            "7. Attack Reconstruction",
            "8. Impact Assessment",
            "9. Containment",
            "10. Recovery",
            "11. Mitigation",
            "12. Conclusion",
        ]
        self._section_btns = []
        for label in self._sections:
            btn = ctk.CTkButton(nav, text=label,
                                command=lambda l=label: self._scroll_to(l),
                                fg_color=COLORS["bg_card"],
                                hover_color=COLORS["bg_hover"],
                                text_color=COLORS["text_secondary"],
                                font=("Consolas", 10),
                                anchor="w",
                                corner_radius=4,
                                height=32)
            btn.pack(fill="x", padx=12, pady=2)
            self._section_btns.append(btn)

        # Main report (right)
        self.report_scroll = ctk.CTkScrollableFrame(body,
                                                     fg_color=COLORS["bg_panel"],
                                                     corner_radius=10,
                                                     border_color=COLORS["border"],
                                                     border_width=1)
        self.report_scroll.grid(row=0, column=1, sticky="nsew")

        self.report_box = ctk.CTkTextbox(self.report_scroll,
                                         fg_color=COLORS["bg_darkest"],
                                         text_color=COLORS["text_primary"],
                                         font=("Courier New", 11),
                                         wrap="word")
        self.report_box.pack(fill="both", expand=True, padx=8, pady=8)
        self.report_box.configure(state="disabled")

        # Configure text tags
        self.report_box.tag_config("h1",
                                   font=("Consolas", 15, "bold"),
                                   foreground=COLORS["accent_blue"])
        self.report_box.tag_config("h2",
                                   font=("Consolas", 12, "bold"),
                                   foreground=COLORS["accent_cyan"])
        self.report_box.tag_config("key",
                                   font=("Consolas", 11),
                                   foreground=COLORS["accent_yellow"])
        self.report_box.tag_config("val",
                                   font=("Courier New", 10),
                                   foreground=COLORS["text_primary"])
        self.report_box.tag_config("note",
                                   font=("Courier New", 10),
                                   foreground=COLORS["text_secondary"])
        self.report_box.tag_config("good",
                                   font=("Consolas", 10),
                                   foreground=COLORS["safe"])
        self.report_box.tag_config("bad",
                                   font=("Consolas", 10),
                                   foreground=COLORS["compromised"])
        self.report_box.tag_config("sep",
                                   font=("Courier New", 10),
                                   foreground=COLORS["text_dim"])

        self._section_positions = {}

    def _generate(self):
        def _run():
            from forensics.timeline import build_investigation_summary, reconstruct_timeline
            from forensics.hashing import verify_all_evidence
            from forensics.file_analyzer import analyze_file_changes
            from forensics.network_analyzer import analyze_smb_traffic
            from database import db_manager

            summary = build_investigation_summary()
            timeline = db_manager.get_timeline()
            evidence = db_manager.get_evidence()
            hash_results = verify_all_evidence()
            file_analysis = analyze_file_changes()
            net_analysis = analyze_smb_traffic()
            machine_states = db_manager.get_machine_states()

            self.after(0, lambda: self._render_report(
                summary, timeline, evidence, hash_results,
                file_analysis, net_analysis, machine_states))

        threading.Thread(target=_run, daemon=True).start()

    def _render_report(self, summary, timeline, evidence, hash_results,
                       file_analysis, net_analysis, machine_states):
        box = self.report_box
        box.configure(state="normal")
        box.delete("1.0", "end")

        def h1(text):
            box.insert("end", "\n" + "═" * 60 + "\n", "sep")
            box.insert("end", f"  {text}\n", "h1")
            box.insert("end", "═" * 60 + "\n\n", "sep")

        def h2(text):
            pos = box.index("end")
            self._section_positions[text] = pos
            box.insert("end", f"{text}\n", "h2")
            box.insert("end", "─" * 40 + "\n", "sep")

        def kv(key, val):
            box.insert("end", f"  {key:<28}", "key")
            box.insert("end", f"{val}\n", "val")

        def para(text):
            box.insert("end", f"  {text}\n", "note")

        def bullet(text, good=False, bad=False):
            tag = "good" if good else ("bad" if bad else "note")
            box.insert("end", f"  • {text}\n", tag)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── Report header ──────────────────────────────────────────────────────
        box.insert("end", "\n")
        box.insert("end",
                   "  ╔══════════════════════════════════════════════════════════╗\n"
                   "  ║       FORENSIC CASE ANALYSIS REPORT                     ║\n"
                   "  ║       WannaCry Ransomware Incident — NHS Simulation      ║\n"
                   "  ║       EDUCATIONAL / ACADEMIC USE ONLY                   ║\n"
                   "  ╚══════════════════════════════════════════════════════════╝\n\n",
                   "h1")
        kv("Case Reference:", "WCL-2017-NHS-001")
        kv("Incident Type:", "Ransomware (WannaCry-style simulation)")
        kv("Organisation:", "NHS Trust Hospital (Simulated)")
        kv("Report Generated:", now)
        kv("Classification:", "EDUCATIONAL SIMULATION")

        # 1. Incident Description
        h1("1. INCIDENT DESCRIPTION")
        para(
            "On 12 May 2017, a WannaCry-style ransomware attack was simulated\n"
            "  against a fictional NHS hospital network. The simulated attack\n"
            "  affected three workstations containing patient records, emergency\n"
            "  department reports, billing records, and administrative documents.\n\n"
            "  The simulation demonstrates the typical WannaCry attack chain:\n"
            "  initial compromise, file system impact, ransom note generation,\n"
            "  and worm-style SMB propagation across the local network."
        )

        # 2. Evidence Identified
        h1("2. EVIDENCE IDENTIFIED")
        kv("Total evidence items:", str(len(evidence)))
        box.insert("end", "\n")
        for ev in evidence[:20]:
            box.insert("end",
                       f"  {ev['evidence_id']:<8}  {ev['evidence_type']:<20}  "
                       f"{ev['machine']:<6}  {ev['filename']}\n", "val")

        # 3. Evidence Integrity
        h1("3. EVIDENCE INTEGRITY")
        verified = sum(1 for r in hash_results if r["status"] == "VERIFIED")
        modified = sum(1 for r in hash_results if r["status"] == "MODIFIED")
        missing  = sum(1 for r in hash_results if r["status"] == "FILE_MISSING")
        kv("Items verified:", str(verified))
        kv("Items modified:", str(modified))
        kv("Items missing:", str(missing))
        box.insert("end", "\n")
        for r in hash_results[:15]:
            status_str = "✓ VERIFIED" if r["status"] == "VERIFIED" else (
                "⚠ MODIFIED" if r["status"] == "MODIFIED" else "? MISSING")
            tag = "good" if r["status"] == "VERIFIED" else "bad"
            box.insert("end",
                       f"  {r['evidence_id']:<8}  {status_str:<14}  {r.get('filename', '')}\n",
                       tag)

        # 4. File-System Findings
        h1("4. FILE-SYSTEM FINDINGS")
        kv("Files in baseline:", str(file_analysis["total_files"]))
        kv("Files affected:", str(file_analysis["affected_count"]))
        kv("Primary indicator:", ".WCRY_SIMULATED extension")
        box.insert("end", "\n")
        para(file_analysis.get("finding", ""))
        box.insert("end", "\n")
        # Sample affected files
        comparison = file_analysis.get("comparison", [])
        affected = [c for c in comparison if c["status"] == "AFFECTED"][:8]
        for c in affected:
            box.insert("end",
                       f"  {c['original_name']}\n"
                       f"    → {c['affected_name']}\n", "bad")

        # 5. Network Findings
        h1("5. NETWORK FINDINGS")
        kv("Total network events:", str(net_analysis["total_events"]))
        kv("SMB/445 events:", str(net_analysis["smb_events"]))
        kv("SMB sources:", ", ".join(net_analysis.get("smb_sources", [])))
        kv("SMB destinations:", ", ".join(net_analysis.get("smb_destinations", [])))
        box.insert("end", "\n")
        para(net_analysis.get("finding", ""))

        # 6. Attack Timeline
        h1("6. RECONSTRUCTED ATTACK TIMELINE")
        for event in timeline[:20]:
            ts = str(event.get("ts", ""))
            time_str = ts[11:19] if "T" in ts else ts[:8]
            desc = event.get("event_description", "")
            eids = event.get("evidence_ids", "")
            box.insert("end", f"\n  [{time_str}]  ", "key")
            box.insert("end", f"{desc}\n", "val")
            if eids:
                box.insert("end", f"           Evidence: {eids}\n", "note")

        # 7. Attack Reconstruction
        h1("7. ATTACK RECONSTRUCTION")
        chain = [
            "INITIAL COMPROMISE (HOSPITAL-PC-01)",
            "    │",
            "    ├── File system impact (.WCRY_SIMULATED)",
            "    ├── Ransom note created (WANNACRY_SIMULATION_NOTE.txt)",
            "    │",
            "    └── Simulated TCP/445 SMB propagation",
            "             │",
            "        ┌────┴────┐",
            "        ▼         ▼",
            "    PC-02          PC-03",
            "        │           │",
            "    File impact  File impact",
        ]
        for line in chain:
            box.insert("end", f"  {line}\n", "val")

        # 8. Impact Assessment
        h1("8. IMPACT ASSESSMENT")
        kv("Compromised hosts:", str(summary.get("affected_hosts", 0)))
        kv("Affected host list:", ", ".join(summary.get("affected_host_list", [])))
        kv("Files impacted:", str(summary.get("total_affected_files", 0)))
        kv("Ransom notes:", str(summary.get("ransom_note_count", 0)))
        kv("Services disrupted:", "Patient records, Emergency dept, Billing")
        kv("Data loss:", "None (simulation — files recoverable from baseline)")
        box.insert("end", "\n")
        para(
            "In the real 2017 WannaCry incident, approximately 80 NHS trusts\n"
            "  were affected, with ~6,900 NHS appointments cancelled and an\n"
            "  estimated £92 million in damage."
        )

        # 9. Containment
        h1("9. CONTAINMENT")
        for pc_id, info in machine_states.items():
            state = info.get("state", "UNKNOWN")
            tag = "good" if state in ("ISOLATED", "RECOVERED") else "bad"
            box.insert("end", f"  {pc_id:<8}  {state}\n", tag)
        box.insert("end", "\n")
        para("Containment: All machines isolated, simulated network access blocked.")

        # 10. Recovery
        h1("10. RECOVERY")
        para(
            "Files restored from pre-incident baseline backup.\n"
            "  Clean file integrity confirmed against original SHA-256 hashes.\n"
            "  Forensic evidence preserved in cases/evidence_archive/."
        )
        kv("Recovery method:", "Baseline file restoration")
        kv("Evidence preserved:", "Yes — not deleted during recovery")
        kv("Containment time:", db_manager_meta("containment_ts"))
        kv("Recovery time:", db_manager_meta("recovery_ts"))

        # 11. Mitigation
        h1("11. MITIGATION RECOMMENDATIONS")
        mitigations = [
            ("CRITICAL", "Apply MS17-010 patch (Windows security update)"),
            ("CRITICAL", "Disable SMBv1 on all systems"),
            ("HIGH", "Implement network segmentation (VLANs)"),
            ("HIGH", "Deploy endpoint detection and response (EDR)"),
            ("HIGH", "Maintain verified offline backups"),
            ("MEDIUM", "Implement SIEM monitoring for lateral movement"),
            ("MEDIUM", "Conduct regular vulnerability assessments"),
            ("MEDIUM", "Staff security awareness training"),
            ("LOW", "Develop and test incident response procedures"),
        ]
        for priority, action in mitigations:
            tag = "bad" if priority == "CRITICAL" else (
                "key" if priority == "HIGH" else "note")
            box.insert("end", f"  [{priority}] {action}\n", tag)

        # 12. Conclusion
        h1("12. CONCLUSION")
        para(
            "This forensic investigation successfully demonstrated the simulation\n"
            "  of a WannaCry-style ransomware incident and its investigation.\n\n"
            "  KEY FINDINGS:\n"
            f"  • Initial compromise: {summary.get('initial_host', '—')}\n"
            f"  • Affected hosts: {summary.get('affected_hosts', 0)}\n"
            f"  • File impact: {summary.get('total_affected_files', 0)} files renamed\n"
            f"  • Network: {summary.get('smb_event_count', 0)} simulated SMB events\n"
            f"  • Ransom notes: {summary.get('ransom_note_count', 0)}\n\n"
            "  ATTRIBUTION:\n"
            f"  {summary.get('attribution', '—')}\n\n"
            "  The attack simulation and forensic investigation demonstrate the\n"
            "  complete cyber incident lifecycle: attack → evidence collection\n"
            "  → timeline reconstruction → containment → recovery → prevention.\n\n"
            "  DISCLAIMER: This is an entirely simulated educational exercise.\n"
            "  No real malware, encryption, or network exploitation was used."
        )

        box.configure(state="disabled")
        self.app.mark_step(16, done=True)
        self.app.log_event("Case analysis report generated", "success")

    def _scroll_to(self, section_label):
        pos = self._section_positions.get(section_label)
        if pos:
            self.report_box.see(pos)

    def _export(self):
        from database import db_manager
        reports_dir = Path(__file__).parent.parent / "reports"
        reports_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = reports_dir / f"WannaCry_Case_Report_{ts}.txt"

        content = self.report_box.get("1.0", "end")
        report_path.write_text(content, encoding="utf-8")

        self.export_lbl.configure(
            text=f"✓ Report exported: reports/WannaCry_Case_Report_{ts}.txt")
        self.app.log_event(f"Report exported to reports/", "success")

    def refresh(self):
        pass


def db_manager_meta(key):
    try:
        from database import db_manager
        return db_manager.get_case_meta(key, "—") or "—"
    except Exception:
        return "—"
