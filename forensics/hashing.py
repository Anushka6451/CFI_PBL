"""
Hashing Module — WannaCry Forensic Lab
SHA-256 calculation and evidence integrity verification.
"""

import hashlib
from pathlib import Path
from database import db_manager


def sha256_of_file(filepath) -> str:
    """Calculate SHA-256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError):
        return "FILE_NOT_FOUND"


def sha256_of_string(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def verify_all_evidence() -> list:
    """
    Verify SHA-256 integrity of all collected evidence.
    Returns list of verification results.
    """
    evidence_list = db_manager.get_evidence()
    results = []

    for ev in evidence_list:
        eid = ev["evidence_id"]
        filepath = ev.get("filepath", "")
        original_hash = ev.get("sha256_acquisition", "")

        if not filepath or not Path(filepath).exists():
            current_hash = "FILE_NOT_ACCESSIBLE"
            status = "FILE_MISSING"
        else:
            current_hash = sha256_of_file(filepath)
            if current_hash == original_hash:
                status = "VERIFIED"
            else:
                status = "MODIFIED"

        db_manager.update_evidence_integrity(eid, current_hash, status)

        results.append({
            "evidence_id": eid,
            "filename": ev.get("filename", ""),
            "machine": ev.get("machine", ""),
            "original_hash": original_hash,
            "current_hash": current_hash,
            "status": status,
        })

    return results
