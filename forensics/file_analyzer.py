"""
File Analyzer — WannaCry Forensic Lab
Compares pre-attack baseline vs post-attack file state.
"""

from pathlib import Path
from database import db_manager
from forensics.hashing import sha256_of_file
from simulation.hospital_environment import get_pc_path, MACHINES

WCRY_EXT = ".WCRY_SIMULATED"


def analyze_file_changes() -> dict:
    """
    Compare baseline vs current file state.
    Returns dict with before/after comparison data.
    """
    baseline = db_manager.get_baseline()
    file_impacts = db_manager.get_file_impacts()

    # Build lookup: machine → {original_name → record}
    baseline_lookup = {}
    for b in baseline:
        key = (b["machine"], b["filename"])
        baseline_lookup[key] = b

    # Build affected lookup
    affected_lookup = {}
    for fi in file_impacts:
        key = (fi["machine"], fi["original_name"])
        affected_lookup[key] = fi

    comparison = []
    for b in baseline:
        key = (b["machine"], b["filename"])
        if key in affected_lookup:
            fi = affected_lookup[key]
            comparison.append({
                "machine": b["machine"],
                "machine_name": MACHINES.get(b["machine"], {}).get("name", b["machine"]),
                "original_name": b["filename"],
                "affected_name": fi["affected_name"],
                "original_sha256": b["sha256"],
                "affected_sha256": fi["affected_sha256"],
                "impact_ts": fi["impact_ts"],
                "baseline_ts": b["modified_ts"],
                "status": "AFFECTED",
                "size_before": b["file_size"],
                "finding": "File renamed with .WCRY_SIMULATED — consistent with ransomware file marking",
            })
        else:
            comparison.append({
                "machine": b["machine"],
                "machine_name": MACHINES.get(b["machine"], {}).get("name", b["machine"]),
                "original_name": b["filename"],
                "affected_name": b["filename"],
                "original_sha256": b["sha256"],
                "affected_sha256": b["sha256"],
                "impact_ts": None,
                "baseline_ts": b["modified_ts"],
                "status": "UNAFFECTED",
                "size_before": b["file_size"],
                "finding": "File unchanged from baseline",
            })

    # Count stats
    total = len(comparison)
    affected = len([c for c in comparison if c["status"] == "AFFECTED"])

    return {
        "comparison": comparison,
        "total_files": total,
        "affected_count": affected,
        "unaffected_count": total - affected,
        "finding": (
            f"{affected} of {total} baseline files were modified. "
            "File renaming pattern (.WCRY_SIMULATED extension) is consistent "
            "with ransomware-style file impact. Changes occurred immediately "
            "after the initial compromise event on each host."
        ),
    }


def get_ransom_notes() -> list:
    """Return all collected ransom note evidence."""
    return db_manager.get_evidence(type_filter="RANSOM_NOTE")


def get_affected_files() -> list:
    """Return all file impact records."""
    return db_manager.get_file_impacts()
