# WannaCry Forensic Investigation Lab

## Cyber Terrorism Incident Simulation & Digital Forensics

> **EDUCATIONAL SIMULATION — NO REAL MALWARE — NO REAL NETWORK ATTACKS**

---

### Overview

A complete Python desktop application that simulates a WannaCry-style ransomware incident against a fictional NHS hospital network and walks investigators through the full forensic investigation process.

**Case Study:** 2017 WannaCry NHS Attack (Simulated)

---

### Requirements

- Python 3.10+
- Windows / macOS / Linux

### Installation & Run

```bash
pip install -r requirements.txt
python main.py
```

---

### Application Flow

```
Normal Hospital System
        ↓
Capture Baseline (SHA-256 hashes)
        ↓
Launch WannaCry Simulation
        ↓
Stage 1 — Initial Infection (PC-01)
        ↓
Stage 2 — File Impact (.WCRY_SIMULATED)
        ↓
Stage 3 — Ransom Note
        ↓
Stage 4 — Simulated Worm Propagation (PC-02, PC-03)
        ↓
Incident Detection
        ↓
Evidence Collection (SHA-256, CSV logs, JSON markers)
        ↓
File & Network Forensic Analysis
        ↓
Hash Verification
        ↓
Timeline Reconstruction (from evidence sources)
        ↓
Attack Reconstruction (visual chain)
        ↓
Case Findings
        ↓
Containment (machine isolation)
        ↓
Recovery (baseline file restoration)
        ↓
Mitigation (second protected simulation)
        ↓
Case Analysis Report (12-section forensic report + export)
```

---

### Project Structure

```
WannaCry_Forensic_Lab/
├── main.py                        # Application entry point
├── requirements.txt
├── README.md
│
├── gui/                           # All GUI pages
│   ├── theme.py                   # Dark forensics color system
│   ├── widgets.py                 # Reusable components
│   ├── page_dashboard.py          # Workflow overview
│   ├── page_network.py            # Hospital network + baseline
│   ├── page_simulation.py         # WannaCry simulation + console
│   ├── page_evidence.py           # Evidence explorer
│   ├── page_file_forensics.py     # Before/after file comparison
│   ├── page_network_forensics.py  # SMB traffic analysis
│   ├── page_hash.py               # SHA-256 verification
│   ├── page_timeline.py           # Timeline reconstruction
│   ├── page_reconstruction.py     # Attack chain visualization
│   ├── page_findings.py           # Investigation findings
│   ├── page_containment.py        # Containment & recovery
│   ├── page_prevention.py         # Mitigation + protected sim
│   └── page_case_analysis.py      # 12-section forensic report
│
├── simulation/
│   ├── hospital_environment.py    # Sandbox file system
│   ├── incident_simulator.py      # Attack stage orchestration
│   └── recovery.py                # Containment & restoration
│
├── forensics/
│   ├── evidence_collector.py      # Evidence cataloging
│   ├── hashing.py                 # SHA-256 & verification
│   ├── file_analyzer.py           # Baseline vs current state
│   ├── network_analyzer.py        # SMB traffic patterns
│   └── timeline.py                # Timeline reconstruction
│
├── database/
│   └── db_manager.py              # SQLite persistence layer
│
├── simulation_lab/                # SANDBOX (created at runtime)
│   ├── PC-01/                     # Virtual machine filesystems
│   ├── PC-02/
│   ├── PC-03/
│   └── _BASELINE_EVIDENCE/        # Pre-attack backup copies
│
├── cases/
│   ├── forensic_case.db           # SQLite database
│   └── evidence_archive/          # Collected evidence + CSV logs
│
└── reports/                       # Exported case reports
```

---

### Safety Guarantees

| Feature | Implementation |
|---------|---------------|
| No real malware | All file ops are simple renames/writes on dummy text files |
| No real encryption | `.WCRY_SIMULATED` extension only — no cryptographic operations |
| No real network | All "SMB events" are synthetic log entries only |
| Sandboxed | All file ops confined to `simulation_lab/` |
| No system changes | No registry, firewall, or OS modifications |
| No external comms | 100% offline — no network calls made |

---

### Problem Statement Addressed

> **"Analyze a cyber terrorism-related incident, identify digital evidence, reconstruct the attack timeline, and prepare a structured forensic case analysis report."**

Each requirement is implemented as a live interactive investigation step, not just a static report.
