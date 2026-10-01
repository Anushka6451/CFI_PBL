"""
Database Manager — WannaCry Forensic Lab
Handles all SQLite persistence for simulation events, evidence, and forensic data.
"""

import sqlite3
import os
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "cases" / "forensic_case.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def initialize_database():
    """Create all tables if they don't exist."""
    conn = get_connection()
    c = conn.cursor()

    # Baseline file records (pre-attack)
    c.execute("""
        CREATE TABLE IF NOT EXISTS baseline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine TEXT NOT NULL,
            filepath TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER,
            sha256 TEXT,
            created_ts TEXT,
            modified_ts TEXT,
            captured_at TEXT
        )
    """)

    # Live simulation events
    c.execute("""
        CREATE TABLE IF NOT EXISTS sim_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_ts TEXT NOT NULL,
            machine TEXT,
            event_type TEXT NOT NULL,
            description TEXT,
            severity TEXT DEFAULT 'INFO'
        )
    """)

    # Network events (synthetic)
    c.execute("""
        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_ts TEXT NOT NULL,
            source_ip TEXT,
            dest_ip TEXT,
            port INTEGER,
            protocol TEXT,
            event_type TEXT,
            description TEXT
        )
    """)

    # Evidence items collected
    c.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT UNIQUE NOT NULL,
            collected_at TEXT,
            machine TEXT,
            evidence_type TEXT,
            filepath TEXT,
            filename TEXT,
            file_size INTEGER,
            sha256_acquisition TEXT,
            sha256_current TEXT,
            description TEXT,
            content_preview TEXT,
            integrity_status TEXT DEFAULT 'PENDING'
        )
    """)

    # File impact records
    c.execute("""
        CREATE TABLE IF NOT EXISTS file_impact (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine TEXT,
            original_path TEXT,
            original_name TEXT,
            affected_path TEXT,
            affected_name TEXT,
            original_sha256 TEXT,
            affected_sha256 TEXT,
            impact_ts TEXT,
            status TEXT DEFAULT 'AFFECTED'
        )
    """)

    # Timeline events (correlated)
    c.execute("""
        CREATE TABLE IF NOT EXISTS timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_ts TEXT NOT NULL,
            event_order INTEGER,
            machine TEXT,
            event_category TEXT,
            event_description TEXT,
            evidence_ids TEXT,
            significance TEXT
        )
    """)

    # Machine states
    c.execute("""
        CREATE TABLE IF NOT EXISTS machine_states (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine TEXT NOT NULL,
            state TEXT NOT NULL,
            changed_at TEXT,
            reason TEXT
        )
    """)

    # Case metadata
    c.execute("""
        CREATE TABLE IF NOT EXISTS case_meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    conn.commit()
    conn.close()


def reset_database():
    """Wipe all tables for a fresh simulation run."""
    conn = get_connection()
    c = conn.cursor()
    tables = ["baseline", "sim_events", "network_events", "evidence",
              "file_impact", "timeline", "machine_states", "case_meta"]
    for t in tables:
        c.execute(f"DELETE FROM {t}")
    conn.commit()
    conn.close()


# ── Baseline ──────────────────────────────────────────────────────────────────

def insert_baseline(machine, filepath, filename, file_size, sha256,
                    created_ts, modified_ts):
    conn = get_connection()
    conn.execute("""
        INSERT INTO baseline
        (machine, filepath, filename, file_size, sha256, created_ts, modified_ts, captured_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (machine, filepath, filename, file_size, sha256, created_ts,
          modified_ts, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def get_baseline():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM baseline ORDER BY machine, filename").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Simulation Events ─────────────────────────────────────────────────────────

def log_sim_event(machine, event_type, description, severity="INFO", ts=None):
    conn = get_connection()
    event_ts = ts or datetime.now().isoformat()
    conn.execute("""
        INSERT INTO sim_events (event_ts, machine, event_type, description, severity)
        VALUES (?, ?, ?, ?, ?)
    """, (event_ts, machine, event_type, description, severity))
    conn.commit()
    conn.close()
    return event_ts


def get_sim_events():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM sim_events ORDER BY event_ts").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Network Events ────────────────────────────────────────────────────────────

def log_network_event(source_ip, dest_ip, port, protocol, event_type, description, ts=None):
    conn = get_connection()
    event_ts = ts or datetime.now().isoformat()
    conn.execute("""
        INSERT INTO network_events
        (event_ts, source_ip, dest_ip, port, protocol, event_type, description)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (event_ts, source_ip, dest_ip, port, protocol, event_type, description))
    conn.commit()
    conn.close()
    return event_ts


def get_network_events():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM network_events ORDER BY event_ts").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Evidence ──────────────────────────────────────────────────────────────────

def insert_evidence(evidence_id, machine, evidence_type, filepath, filename,
                    file_size, sha256_acquisition, description, content_preview=""):
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO evidence
        (evidence_id, collected_at, machine, evidence_type, filepath, filename,
         file_size, sha256_acquisition, sha256_current, description,
         content_preview, integrity_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (evidence_id, datetime.now().isoformat(), machine, evidence_type,
          filepath, filename, file_size, sha256_acquisition, sha256_acquisition,
          description, content_preview, "PENDING"))
    conn.commit()
    conn.close()


def get_evidence(search=None, machine_filter=None, type_filter=None):
    conn = get_connection()
    query = "SELECT * FROM evidence WHERE 1=1"
    params = []
    if search:
        query += " AND (filename LIKE ? OR description LIKE ? OR evidence_id LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if machine_filter and machine_filter != "ALL":
        query += " AND machine = ?"
        params.append(machine_filter)
    if type_filter and type_filter != "ALL":
        query += " AND evidence_type = ?"
        params.append(type_filter)
    query += " ORDER BY collected_at"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_evidence_integrity(evidence_id, sha256_current, status):
    conn = get_connection()
    conn.execute("""
        UPDATE evidence SET sha256_current=?, integrity_status=? WHERE evidence_id=?
    """, (sha256_current, status, evidence_id))
    conn.commit()
    conn.close()


# ── File Impact ───────────────────────────────────────────────────────────────

def insert_file_impact(machine, original_path, original_name, affected_path,
                       affected_name, original_sha256, affected_sha256, ts=None):
    conn = get_connection()
    impact_ts = ts or datetime.now().isoformat()
    conn.execute("""
        INSERT INTO file_impact
        (machine, original_path, original_name, affected_path, affected_name,
         original_sha256, affected_sha256, impact_ts, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'AFFECTED')
    """, (machine, original_path, original_name, affected_path, affected_name,
          original_sha256, affected_sha256, impact_ts))
    conn.commit()
    conn.close()


def get_file_impacts():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM file_impact ORDER BY impact_ts").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_file_impact_status(machine, status):
    conn = get_connection()
    conn.execute("UPDATE file_impact SET status=? WHERE machine=?", (status, machine))
    conn.commit()
    conn.close()


# ── Timeline ──────────────────────────────────────────────────────────────────

def insert_timeline_event(event_ts, event_order, machine, category,
                          description, evidence_ids="", significance=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO timeline
        (event_ts, event_order, machine, event_category, event_description,
         evidence_ids, significance)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (event_ts, event_order, machine, category, description,
          evidence_ids, significance))
    conn.commit()
    conn.close()


def get_timeline():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM timeline ORDER BY event_order, event_ts").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Machine States ────────────────────────────────────────────────────────────

def log_machine_state(machine, state, reason=""):
    conn = get_connection()
    conn.execute("""
        INSERT INTO machine_states (machine, state, changed_at, reason)
        VALUES (?, ?, ?, ?)
    """, (machine, state, datetime.now().isoformat(), reason))
    conn.commit()
    conn.close()


def get_machine_states():
    conn = get_connection()
    rows = conn.execute("""
        SELECT machine, state, changed_at, reason FROM machine_states
        WHERE id IN (
            SELECT MAX(id) FROM machine_states GROUP BY machine
        )
    """).fetchall()
    conn.close()
    return {r["machine"]: dict(r) for r in rows}


# ── Case Meta ─────────────────────────────────────────────────────────────────

def set_case_meta(key, value):
    conn = get_connection()
    conn.execute("INSERT OR REPLACE INTO case_meta (key, value) VALUES (?, ?)",
                 (key, str(value)))
    conn.commit()
    conn.close()


def get_case_meta(key, default=None):
    conn = get_connection()
    row = conn.execute("SELECT value FROM case_meta WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default
