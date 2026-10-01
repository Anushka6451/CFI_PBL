"""
Evidence Collector — WannaCry Forensic Lab
Systematically collects and catalogs all forensic evidence from the simulation.
"""

import csv
import json
from pathlib import Path
from datetime import datetime

from database import db_manager
from forensics.hashing import sha256_of_file
from simulation.hospital_environment import (
    get_pc_path, MACHINES, PC_DIRS
)

WCRY_EXT = ".WCRY_SIMULATED"
EVIDENCE_COUNTER = [0]  # mutable list so inner functions can update it

EVIDENCE_DIR = Path(__file__).parent.parent / "cases" / "evidence_archive"


def _next_eid() -> str:
    EVIDENCE_COUNTER[0] += 1
    return f"E-{EVIDENCE_COUNTER[0]:03d}"


def reset_counter():
    EVIDENCE_COUNTER[0] = 0


def collect_all_evidence() -> list:
    """
    Main evidence collection routine.
    Scans simulation_lab for all forensic artifacts and registers them.
    """
    reset_counter()
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    collected = []

    for pc_id in MACHINES:
        pc_path = get_pc_path(pc_id)
        if not pc_path.exists():
            continue

        for fpath in pc_path.rglob("*"):
            if not fpath.is_file():
                continue

            fname = fpath.name
            stat = fpath.stat()
            sha = sha256_of_file(fpath)
            eid = _next_eid()

            # Determine evidence type
            if WCRY_EXT in fname:
                ev_type = "AFFECTED_FILE"
                desc = f"File renamed with ransomware extension on {MACHINES[pc_id]['name']}"
            elif fname == "infection_marker.json":
                ev_type = "INFECTION_MARKER"
                desc = f"Infection marker JSON artifact on {MACHINES[pc_id]['name']}"
            elif fname == "WANNACRY_SIMULATION_NOTE.txt":
                ev_type = "RANSOM_NOTE"
                desc = f"Ransomware-style note found on {MACHINES[pc_id]['name']}"
            else:
                ev_type = "DOCUMENT"
                desc = f"Document file found during evidence sweep of {MACHINES[pc_id]['name']}"

            # Read a safe preview
            try:
                content_preview = fpath.read_text(encoding="utf-8", errors="replace")[:300]
            except Exception:
                content_preview = "[binary or unreadable]"

            db_manager.insert_evidence(
                eid, pc_id, ev_type, str(fpath), fname,
                stat.st_size, sha, desc, content_preview
            )

            collected.append({
                "evidence_id": eid,
                "machine": pc_id,
                "evidence_type": ev_type,
                "filename": fname,
                "filepath": str(fpath),
                "sha256": sha,
                "description": desc,
            })

    # Export endpoint events CSV
    _export_endpoint_csv()

    # Export network events CSV
    _export_network_csv()

    db_manager.set_case_meta("evidence_collected_ts", datetime.now().isoformat())
    db_manager.set_case_meta("evidence_count", str(len(collected)))
    return collected


def _export_endpoint_csv():
    """Export simulation events as endpoint_events.csv evidence."""
    events = db_manager.get_sim_events()
    csv_path = EVIDENCE_DIR / "endpoint_events.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["id", "event_ts", "machine",
                                          "event_type", "description", "severity"])
        w.writeheader()
        for e in events:
            w.writerow({k: e.get(k, "") for k in w.fieldnames})

    sha = sha256_of_file(csv_path)
    eid = _next_eid()
    db_manager.insert_evidence(
        eid, "ALL", "ENDPOINT_LOG", str(csv_path), "endpoint_events.csv",
        csv_path.stat().st_size, sha,
        "Endpoint event log CSV — all simulation activity records",
        f"[{len(events)} events recorded]"
    )


def _export_network_csv():
    """Export network events as network_events.csv evidence."""
    events = db_manager.get_network_events()
    csv_path = EVIDENCE_DIR / "network_events.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["id", "event_ts", "source_ip",
                                          "dest_ip", "port", "protocol",
                                          "event_type", "description"])
        w.writeheader()
        for e in events:
            w.writerow({k: e.get(k, "") for k in w.fieldnames})

    sha = sha256_of_file(csv_path)
    eid = _next_eid()
    db_manager.insert_evidence(
        eid, "ALL", "NETWORK_LOG", str(csv_path), "network_events.csv",
        csv_path.stat().st_size, sha,
        "Network event log CSV — synthetic SMB propagation events",
        f"[{len(events)} network events recorded]"
    )
