"""
Hospital Environment — WannaCry Forensic Lab
Creates and manages the simulated hospital file system sandbox.
ALL file operations are confined to simulation_lab/ inside the project folder.
"""

import os
import shutil
import json
import hashlib
from pathlib import Path
from datetime import datetime

from database import db_manager

# Root of the entire sandbox — NEVER leaves this directory
LAB_ROOT = Path(__file__).parent.parent / "simulation_lab"
BASELINE_ROOT = Path(__file__).parent.parent / "simulation_lab" / "_BASELINE_EVIDENCE"

MACHINES = {
    "PC-01": {"name": "HOSPITAL-PC-01", "ip": "192.168.56.10"},
    "PC-02": {"name": "HOSPITAL-PC-02", "ip": "192.168.56.20"},
    "PC-03": {"name": "HOSPITAL-PC-03", "ip": "192.168.56.30"},
}

# File content templates — dummy hospital documents
FILE_TEMPLATES = {
    "Patient_Records": {
        "Patient_001.txt": (
            "PATIENT RECORD — NHS SIMULATION\n"
            "Patient ID: PAT-001\nName: John Smith\nDOB: 15/03/1965\n"
            "Ward: Emergency\nDiagnosis: Hypertension\nStatus: Admitted\n"
            "Last Updated: 2017-05-12 08:30:00\n"
            "[EDUCATIONAL SIMULATION — NOT REAL PATIENT DATA]"
        ),
        "Patient_002.txt": (
            "PATIENT RECORD — NHS SIMULATION\n"
            "Patient ID: PAT-002\nName: Mary Johnson\nDOB: 22/07/1978\n"
            "Ward: Cardiology\nDiagnosis: Arrhythmia\nStatus: Under observation\n"
            "Last Updated: 2017-05-12 09:00:00\n"
            "[EDUCATIONAL SIMULATION — NOT REAL PATIENT DATA]"
        ),
        "Patient_003.txt": (
            "PATIENT RECORD — NHS SIMULATION\n"
            "Patient ID: PAT-003\nName: Robert Brown\nDOB: 03/11/1950\n"
            "Ward: Surgery\nDiagnosis: Appendicitis\nStatus: Pre-operative\n"
            "Last Updated: 2017-05-12 09:15:00\n"
            "[EDUCATIONAL SIMULATION — NOT REAL PATIENT DATA]"
        ),
    },
    "Emergency": {
        "Emergency_Report_Alpha.txt": (
            "EMERGENCY DEPARTMENT REPORT — NHS SIMULATION\n"
            "Report ID: EMR-2017-001\nDate: 2017-05-12\nShift: Morning\n"
            "Total Admissions: 24\nCritical Cases: 3\nBed Occupancy: 87%\n"
            "Staff on duty: Dr. Evans, Dr. Patel, Sr. Nurse Williams\n"
            "[EDUCATIONAL SIMULATION — NOT REAL HOSPITAL DATA]"
        ),
        "Triage_Log.txt": (
            "TRIAGE LOG — NHS SIMULATION\n"
            "Date: 2017-05-12\nPatients assessed: 18\n"
            "Priority 1 (Immediate): 2\nPriority 2 (Urgent): 7\n"
            "Priority 3 (Non-urgent): 9\n"
            "[EDUCATIONAL SIMULATION — NOT REAL TRIAGE DATA]"
        ),
    },
    "Billing": {
        "Billing_Record_May2017.txt": (
            "BILLING RECORD — NHS SIMULATION\n"
            "Period: May 2017\nDepartment: Emergency\n"
            "Total Procedures: 142\nProcessed Claims: 98\nPending Claims: 44\n"
            "Total Value: £142,300\n"
            "[EDUCATIONAL SIMULATION — NOT REAL FINANCIAL DATA]"
        ),
        "Staff_Payroll_Q1.txt": (
            "STAFF PAYROLL — NHS SIMULATION\n"
            "Quarter: Q1 2017\nDepartment: All\n"
            "Total Staff: 48\nTotal Payroll: £284,000\n"
            "Status: PROCESSED\n"
            "[EDUCATIONAL SIMULATION — NOT REAL PAYROLL DATA]"
        ),
    },
    "Administration": {
        "Staff_List.txt": (
            "STAFF DIRECTORY — NHS SIMULATION\n"
            "Chief Medical Officer: Dr. Sarah Evans\n"
            "Head of Emergency: Dr. Raj Patel\n"
            "Head of Cardiology: Dr. Liu Zhang\n"
            "IT Manager: James Morrison\n"
            "Systems Administrator: Claire Hughes\n"
            "Total Staff: 48\n"
            "[EDUCATIONAL SIMULATION — NOT REAL STAFF DATA]"
        ),
        "Network_Config.txt": (
            "NETWORK CONFIGURATION — NHS SIMULATION\n"
            "Site: NHS Trust Hospital\nSubnet: 192.168.56.0/24\n"
            "VLAN 10: Clinical Systems\nVLAN 20: Administrative\n"
            "Primary DNS: 192.168.56.1\nGateway: 192.168.56.254\n"
            "Note: SMBv1 enabled on legacy systems (vulnerability)\n"
            "[EDUCATIONAL SIMULATION — NOT REAL NETWORK DATA]"
        ),
    },
}

# Which directories each PC has
PC_DIRS = {
    "PC-01": ["Patient_Records", "Emergency", "Billing"],
    "PC-02": ["Patient_Records", "Administration", "Billing"],
    "PC-03": ["Emergency", "Administration", "Patient_Records"],
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def create_hospital_environment():
    """
    Build the simulation_lab directory tree with dummy hospital files.
    Returns list of created files.
    """
    # Always start fresh
    if LAB_ROOT.exists():
        shutil.rmtree(LAB_ROOT)
    LAB_ROOT.mkdir(parents=True)
    BASELINE_ROOT.mkdir(parents=True)

    created = []
    for pc_id, dirs in PC_DIRS.items():
        pc_path = LAB_ROOT / pc_id
        pc_path.mkdir()
        for dir_name in dirs:
            dir_path = pc_path / dir_name
            dir_path.mkdir()
            templates = FILE_TEMPLATES.get(dir_name, {})
            for fname, content in templates.items():
                fpath = dir_path / fname
                fpath.write_text(content, encoding="utf-8")
                created.append({
                    "machine": pc_id,
                    "machine_name": MACHINES[pc_id]["name"],
                    "dir": dir_name,
                    "filename": fname,
                    "path": str(fpath),
                })
    return created


def capture_baseline() -> list:
    """
    Record SHA-256, size, and timestamps for all sandbox files.
    Also save copies to BASELINE_EVIDENCE folder for recovery.
    Returns list of baseline records.
    """
    records = []
    for pc_id in PC_DIRS:
        pc_path = LAB_ROOT / pc_id
        if not pc_path.exists():
            continue
        # Mirror in baseline
        baseline_pc = BASELINE_ROOT / pc_id
        if baseline_pc.exists():
            shutil.rmtree(baseline_pc)
        shutil.copytree(pc_path, baseline_pc)

        for fpath in pc_path.rglob("*"):
            if fpath.is_file():
                stat = fpath.stat()
                sha = sha256_file(fpath)
                created_ts = datetime.fromtimestamp(stat.st_ctime).isoformat()
                modified_ts = datetime.fromtimestamp(stat.st_mtime).isoformat()
                rec = {
                    "machine": pc_id,
                    "filepath": str(fpath),
                    "filename": fpath.name,
                    "file_size": stat.st_size,
                    "sha256": sha,
                    "created_ts": created_ts,
                    "modified_ts": modified_ts,
                }
                records.append(rec)
                db_manager.insert_baseline(
                    pc_id, str(fpath), fpath.name, stat.st_size,
                    sha, created_ts, modified_ts
                )

    db_manager.set_case_meta("baseline_captured", datetime.now().isoformat())
    db_manager.set_case_meta("baseline_file_count", str(len(records)))
    return records


def get_all_lab_files(machine_filter=None):
    """Return current state of all files in the simulation lab."""
    files = []
    for pc_id in PC_DIRS:
        if machine_filter and pc_id != machine_filter:
            continue
        pc_path = LAB_ROOT / pc_id
        if not pc_path.exists():
            continue
        for fpath in pc_path.rglob("*"):
            if fpath.is_file() and not fpath.name.startswith("."):
                stat = fpath.stat()
                files.append({
                    "machine": pc_id,
                    "filepath": str(fpath),
                    "filename": fpath.name,
                    "file_size": stat.st_size,
                    "modified_ts": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "is_affected": ".WCRY_SIMULATED" in fpath.name,
                    "is_marker": fpath.name == "infection_marker.json",
                    "is_ransom": fpath.name == "WANNACRY_SIMULATION_NOTE.txt",
                })
    return files


def get_pc_path(pc_id: str) -> Path:
    return LAB_ROOT / pc_id


def get_baseline_path(pc_id: str) -> Path:
    return BASELINE_ROOT / pc_id
