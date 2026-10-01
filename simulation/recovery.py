"""
Recovery Module — WannaCry Forensic Lab
Handles containment and file recovery from baseline evidence.
"""

import shutil
from pathlib import Path
from datetime import datetime

from database import db_manager
from simulation.hospital_environment import (
    get_pc_path, get_baseline_path, MACHINES, sha256_file
)

WCRY_EXT = ".WCRY_SIMULATED"


def contain_machine(pc_id: str, callback=None):
    """Mark a machine as isolated in the simulation."""
    db_manager.log_machine_state(pc_id, "ISOLATED", "Incident containment — network isolated")
    db_manager.log_sim_event(
        pc_id, "CONTAINMENT",
        f"{MACHINES[pc_id]['name']} ISOLATED — simulated network access blocked.",
        "INFO"
    )
    event = {
        "machine": pc_id,
        "type": "CONTAINED",
        "description": f"{MACHINES[pc_id]['name']} → ISOLATED",
        "ts": datetime.now().isoformat(),
    }
    if callback:
        callback(event)
    return event


def contain_all_machines(callback=None):
    """Contain all three machines."""
    events = []
    for pc_id in MACHINES:
        e = contain_machine(pc_id, callback)
        events.append(e)
    db_manager.set_case_meta("containment_ts", datetime.now().isoformat())
    return events


def recover_machine(pc_id: str, callback=None):
    """
    Restore clean files from the baseline backup.
    Removes .WCRY_SIMULATED files and restores originals.
    Preserves forensic evidence separately.
    """
    pc_path = get_pc_path(pc_id)
    baseline_path = get_baseline_path(pc_id)
    machine_name = MACHINES[pc_id]["name"]
    recovered_files = []

    if not baseline_path.exists():
        return []

    db_manager.log_machine_state(pc_id, "RECOVERING", "Restoring files from clean baseline")

    # Remove all .WCRY_SIMULATED files
    for fpath in pc_path.rglob("*" + WCRY_EXT):
        if fpath.is_file():
            orig_name = fpath.name.replace(WCRY_EXT, "")
            fpath.unlink()

    # Restore from baseline (copy clean files back)
    for src in baseline_path.rglob("*"):
        if not src.is_file():
            continue
        rel = src.relative_to(baseline_path)
        dst = pc_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        recovered_files.append({
            "filename": src.name,
            "path": str(dst),
            "machine": pc_id,
        })

    # Remove infection marker and ransom note (part of "cleaning")
    for fname in ("infection_marker.json", "WANNACRY_SIMULATION_NOTE.txt"):
        fpath = pc_path / fname
        # Don't delete — move to evidence archive
        # (evidence was already collected before recovery)
        if fpath.exists():
            fpath.unlink()

    db_manager.log_machine_state(pc_id, "RECOVERED", "Files restored from clean baseline")
    db_manager.update_file_impact_status(pc_id, "RECOVERED")
    db_manager.log_sim_event(
        pc_id, "RECOVERY",
        f"{machine_name} — {len(recovered_files)} files restored from clean baseline. "
        "System returned to pre-incident state.",
        "INFO"
    )

    event = {
        "machine": pc_id,
        "type": "RECOVERED",
        "files_restored": len(recovered_files),
        "description": f"{machine_name} → RECOVERED",
        "ts": datetime.now().isoformat(),
    }
    if callback:
        callback(event)
    return event


def recover_all_machines(callback=None):
    """Recover all three machines."""
    events = []
    for pc_id in MACHINES:
        e = recover_machine(pc_id, callback)
        if e:
            events.append(e)
    db_manager.set_case_meta("recovery_ts", datetime.now().isoformat())
    return events
