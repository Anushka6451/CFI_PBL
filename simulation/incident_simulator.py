"""
Incident Simulator — WannaCry Forensic Lab
Orchestrates the step-by-step WannaCry-style attack simulation.
ALL operations are on sandbox files only. No real malware or network attacks.
"""

import json
import hashlib
import shutil
import time
from pathlib import Path
from datetime import datetime, timedelta

from database import db_manager
from simulation.hospital_environment import (
    get_pc_path, MACHINES, sha256_file, PC_DIRS
)

WCRY_EXT = ".WCRY_SIMULATED"
SIM_BASE_TIME = None  # Set at simulation start


def _sim_time(offset_seconds=0) -> str:
    """Return a simulated timestamp offset from simulation start."""
    global SIM_BASE_TIME
    if SIM_BASE_TIME is None:
        SIM_BASE_TIME = datetime.now()
    return (SIM_BASE_TIME + timedelta(seconds=offset_seconds)).strftime("%H:%M:%S")


def _sim_iso(offset_seconds=0) -> str:
    global SIM_BASE_TIME
    if SIM_BASE_TIME is None:
        SIM_BASE_TIME = datetime.now()
    return (SIM_BASE_TIME + timedelta(seconds=offset_seconds)).isoformat()


def reset_sim_time():
    global SIM_BASE_TIME
    SIM_BASE_TIME = datetime.now()


def stage1_initial_infection(pc_id="PC-01", callback=None):
    """
    Stage 1: Initial compromise of PC-01.
    Creates infection_marker.json as forensic artifact.
    Returns event record.
    """
    ts = _sim_iso(2)
    pc_path = get_pc_path(pc_id)
    machine_name = MACHINES[pc_id]["name"]

    # Create infection marker
    marker_data = {
        "machine": machine_name,
        "ip": MACHINES[pc_id]["ip"],
        "simulation": True,
        "status": "COMPROMISED",
        "threat": "WannaCry-style ransomware simulation",
        "vector": "Simulated SMB vulnerability (EternalBlue-style — EDUCATIONAL ONLY)",
        "timestamp": ts,
        "note": "THIS IS AN EDUCATIONAL SIMULATION — NO REAL MALWARE",
        "artifact_type": "INFECTION_MARKER",
    }
    marker_path = pc_path / "infection_marker.json"
    marker_path.write_text(json.dumps(marker_data, indent=2), encoding="utf-8")

    # Log
    db_manager.log_sim_event(pc_id, "INITIAL_COMPROMISE",
                             f"Initial compromise detected on {machine_name}. "
                             "Simulated ransomware dropper executed.",
                             "CRITICAL", ts)
    db_manager.log_machine_state(pc_id, "COMPROMISED", "Initial WannaCry-style infection")
    db_manager.set_case_meta("attack_start_ts", ts)
    db_manager.set_case_meta("patient_zero", pc_id)

    event = {
        "ts": ts,
        "machine": pc_id,
        "machine_name": machine_name,
        "type": "INITIAL_COMPROMISE",
        "description": f"Initial compromise detected on {machine_name}",
        "marker_path": str(marker_path),
    }
    if callback:
        callback(event)
    return event


def stage2_file_impact(pc_id="PC-01", callback=None):
    """
    Stage 2: Simulate ransomware file impact by renaming dummy files.
    Copies originals to baseline (already done), then renames with .WCRY_SIMULATED.
    """
    pc_path = get_pc_path(pc_id)
    affected = []
    offset = 4  # seconds after start

    for fpath in list(pc_path.rglob("*")):
        if not fpath.is_file():
            continue
        # Skip already processed or special files
        if WCRY_EXT in fpath.name:
            continue
        if fpath.name in ("infection_marker.json", "WANNACRY_SIMULATION_NOTE.txt"):
            continue
        # Skip non-document files
        if fpath.suffix not in (".txt", ".csv", ".pdf", ".doc", ".docx"):
            continue

        ts = _sim_iso(offset)
        orig_sha = sha256_file(fpath)
        orig_path = str(fpath)
        orig_name = fpath.name

        # Rename: Patient_001.txt → Patient_001.txt.WCRY_SIMULATED
        new_path = fpath.with_name(fpath.name + WCRY_EXT)
        fpath.rename(new_path)

        affected_sha = sha256_file(new_path)

        db_manager.insert_file_impact(
            pc_id, orig_path, orig_name, str(new_path), new_path.name,
            orig_sha, affected_sha, ts
        )
        db_manager.log_sim_event(
            pc_id, "FILE_IMPACT",
            f"File renamed: {orig_name} → {new_path.name}",
            "HIGH", ts
        )

        event = {
            "ts": ts,
            "machine": pc_id,
            "type": "FILE_IMPACT",
            "original": orig_name,
            "affected": new_path.name,
            "sha256_before": orig_sha,
            "sha256_after": affected_sha,
        }
        affected.append(event)
        if callback:
            callback(event)
        offset += 2

    return affected


def stage3_ransom_note(pc_id="PC-01", callback=None):
    """Stage 3: Create simulated ransom note."""
    ts = _sim_iso(10)
    pc_path = get_pc_path(pc_id)
    machine_name = MACHINES[pc_id]["name"]

    note_content = (
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║         WANNACRY FORENSIC LAB — EDUCATIONAL SIMULATION       ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n\n"
        "Ooops, your files have been SIMULATED as encrypted!\n\n"
        "Files on this simulated workstation have been marked as affected\n"
        "to demonstrate the impact of ransomware.\n\n"
        "THIS IS AN EDUCATIONAL SIMULATION.\n"
        "No actual encryption or malware has been used.\n"
        "No real files outside simulation_lab/ have been modified.\n\n"
        "── SIMULATION CONTEXT ──────────────────────────────────────────\n"
        "Incident: WannaCry-style ransomware simulation\n"
        f"Affected system: {machine_name}\n"
        "Date: 2017-05-12 (simulated)\n"
        "Real-world reference: 2017 WannaCry NHS attack\n\n"
        "── EDUCATIONAL PURPOSE ─────────────────────────────────────────\n"
        "This simulation is part of a cyber forensics investigation lab.\n"
        "Students are tasked with:\n"
        "  1. Collecting digital evidence\n"
        "  2. Reconstructing the attack timeline\n"
        "  3. Identifying indicators of compromise\n"
        "  4. Preparing a forensic case analysis report\n\n"
        "── WANNACRY HISTORY (REAL INCIDENT) ────────────────────────────\n"
        "On 12 May 2017, the actual WannaCry ransomware attacked\n"
        "over 200,000 systems worldwide, including ~80 NHS trusts in\n"
        "England. It exploited MS17-010 (EternalBlue) vulnerability.\n"
        "This simulation recreates that incident for academic study.\n\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  FORENSIC ARTIFACT — EVIDENCE ITEM — DO NOT DELETE          ║\n"
        "║  SHA-256 will be verified during investigation              ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n"
    )
    note_path = pc_path / "WANNACRY_SIMULATION_NOTE.txt"
    note_path.write_text(note_content, encoding="utf-8")
    note_sha = sha256_file(note_path)
    stat = note_path.stat()

    db_manager.log_sim_event(pc_id, "RANSOM_NOTE",
                             f"Ransom-style note created on {machine_name}: "
                             "WANNACRY_SIMULATION_NOTE.txt",
                             "HIGH", ts)
    db_manager.set_case_meta(f"ransom_note_{pc_id}", str(note_path))

    event = {
        "ts": ts,
        "machine": pc_id,
        "type": "RANSOM_NOTE",
        "path": str(note_path),
        "sha256": note_sha,
        "size": stat.st_size,
    }
    if callback:
        callback(event)
    return event


def stage4_propagation(source_pc="PC-01", target_pc="PC-02",
                       offset=20, callback=None):
    """
    Stage 4: Simulate worm-style SMB propagation between hosts.
    No real network access. Pure Python internal simulation.
    """
    source_name = MACHINES[source_pc]["name"]
    target_name = MACHINES[target_pc]["name"]
    source_ip = MACHINES[source_pc]["ip"]
    target_ip = MACHINES[target_pc]["ip"]
    ts_attempt = _sim_iso(offset)
    ts_compromise = _sim_iso(offset + 2)

    # Log network event
    db_manager.log_network_event(
        source_ip, target_ip, 445, "TCP/SMB",
        "PROPAGATION_ATTEMPT",
        f"Simulated SMB propagation attempt {source_name} → {target_name} "
        f"port 445. EDUCATIONAL SIMULATION — no real SMB exploit used.",
        ts_attempt
    )
    db_manager.log_sim_event(
        source_pc, "PROPAGATION",
        f"TCP/445 propagation attempt: {source_ip} → {target_ip}",
        "HIGH", ts_attempt
    )

    # Target gets compromised
    db_manager.log_machine_state(target_pc, "COMPROMISED",
                                 f"Propagated from {source_name} via simulated SMB")
    db_manager.log_sim_event(
        target_pc, "PROPAGATED",
        f"{target_name} compromised via simulated propagation from {source_name}",
        "CRITICAL", ts_compromise
    )

    events = [
        {
            "ts": ts_attempt,
            "machine": source_pc,
            "type": "PROPAGATION_ATTEMPT",
            "source": source_pc,
            "target": target_pc,
            "source_ip": source_ip,
            "target_ip": target_ip,
            "port": 445,
            "description": f"Simulated SMB/445 propagation: {source_ip} → {target_ip}",
        },
        {
            "ts": ts_compromise,
            "machine": target_pc,
            "type": "HOST_COMPROMISED",
            "description": f"{target_name} compromised",
        }
    ]

    for e in events:
        if callback:
            callback(e)

    return events


def stage_declare_incident(callback=None):
    """Mark the incident as declared after threshold is reached."""
    ts = _sim_iso(35)
    db_manager.log_sim_event(
        "ALL", "INCIDENT_DECLARED",
        "CYBER INCIDENT DECLARED: Multiple hosts compromised. "
        "File impact detected across network. Ransomware-style activity confirmed.",
        "CRITICAL", ts
    )
    db_manager.set_case_meta("incident_declared_ts", ts)

    event = {
        "ts": ts,
        "type": "INCIDENT_DECLARED",
        "description": "CYBER INCIDENT DECLARED",
    }
    if callback:
        callback(event)
    return event


def run_full_simulation(event_callback=None):
    """
    Run the complete simulation sequence.
    event_callback(event_dict) is called for each stage event.
    Returns list of all events generated.
    """
    reset_sim_time()
    all_events = []

    def cb(e):
        all_events.append(e)
        if event_callback:
            event_callback(e)

    # Stage 1: Initial infection on PC-01
    e = stage1_initial_infection("PC-01", cb)

    # Stage 2: File impact on PC-01
    events = stage2_file_impact("PC-01", cb)

    # Stage 3: Ransom note on PC-01
    e = stage3_ransom_note("PC-01", cb)

    # Stage 4: Propagation PC-01 → PC-02
    events = stage4_propagation("PC-01", "PC-02", offset=20, callback=cb)

    # File impact and ransom note on PC-02
    events = stage2_file_impact("PC-02", cb)
    e = stage3_ransom_note("PC-02", cb)

    # Stage 4: Propagation PC-01 → PC-03
    events = stage4_propagation("PC-01", "PC-03", offset=28, callback=cb)

    # File impact and ransom note on PC-03
    events = stage2_file_impact("PC-03", cb)
    e = stage3_ransom_note("PC-03", cb)

    # Declare incident
    e = stage_declare_incident(cb)

    return all_events


# ── Protected simulation (second run with security controls) ──────────────────

def run_protected_simulation(event_callback=None):
    """
    Second run: Security controls block propagation.
    PC-01 gets compromised but PC-02 and PC-03 are protected.
    """
    reset_sim_time()
    all_events = []

    def cb(e):
        all_events.append(e)
        if event_callback:
            event_callback(e)

    # PC-01 still gets initially compromised
    e = stage1_initial_infection("PC-01", cb)
    events = stage2_file_impact("PC-01", cb)
    e = stage3_ransom_note("PC-01", cb)

    # Propagation attempt — BLOCKED
    ts_attempt = _sim_iso(20)
    ts_blocked = _sim_iso(21)
    source_ip = MACHINES["PC-01"]["ip"]

    for target_pc in ["PC-02", "PC-03"]:
        target_ip = MACHINES[target_pc]["ip"]
        target_name = MACHINES[target_pc]["name"]

        db_manager.log_network_event(
            source_ip, target_ip, 445, "TCP/SMB",
            "PROPAGATION_BLOCKED",
            f"Simulated SMB propagation BLOCKED by security controls. "
            f"{target_name} PROTECTED. (Patch applied, SMBv1 disabled, "
            f"network segmentation active)",
            ts_attempt
        )
        db_manager.log_sim_event(
            "PC-01", "PROPAGATION_BLOCKED",
            f"SECURITY CONTROL: Propagation to {target_ip} BLOCKED. "
            f"{target_name} remains SAFE.",
            "INFO", ts_blocked
        )
        db_manager.log_machine_state(target_pc, "PROTECTED",
                                     "Security controls prevented infection")

        event = {
            "ts": ts_blocked,
            "machine": target_pc,
            "type": "PROPAGATION_BLOCKED",
            "target_ip": target_ip,
            "description": f"SECURITY CONTROL BLOCKED propagation to {target_name}",
            "target": target_pc,
        }
        cb(event)

    ts_isolated = _sim_iso(25)
    db_manager.log_machine_state("PC-01", "ISOLATED", "Isolated by security team")
    db_manager.log_sim_event(
        "PC-01", "CONTAINMENT",
        "PC-01 automatically isolated by endpoint protection.",
        "INFO", ts_isolated
    )
    e = {
        "ts": ts_isolated,
        "type": "AUTO_ISOLATED",
        "machine": "PC-01",
        "description": "PC-01 isolated by security controls",
    }
    cb(e)

    return all_events
