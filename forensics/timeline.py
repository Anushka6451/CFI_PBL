"""
Timeline Module — WannaCry Forensic Lab
Reconstructs the attack timeline by correlating evidence sources.
"""

from datetime import datetime
from database import db_manager


def reconstruct_timeline() -> list:
    """
    Build a forensically-sourced attack timeline by correlating:
    - Simulation events (endpoint logs)
    - Network events
    - File impact records
    - Evidence metadata
    Returns list of ordered timeline events.
    """
    _conn = db_manager.get_connection()
    _conn.execute("DELETE FROM timeline")
    _conn.commit()
    _conn.close()

    sim_events = db_manager.get_sim_events()
    net_events = db_manager.get_network_events()
    file_impacts = db_manager.get_file_impacts()
    evidence_list = db_manager.get_evidence()

    # Build evidence lookup by type
    marker_evidence = [e for e in evidence_list if e["evidence_type"] == "INFECTION_MARKER"]
    ransom_evidence = [e for e in evidence_list if e["evidence_type"] == "RANSOM_NOTE"]
    affected_evidence = [e for e in evidence_list if e["evidence_type"] == "AFFECTED_FILE"]
    endpoint_logs = [e for e in evidence_list if e["evidence_type"] == "ENDPOINT_LOG"]
    network_logs = [e for e in evidence_list if e["evidence_type"] == "NETWORK_LOG"]

    raw_events = []

    # Pull from simulation events
    for e in sim_events:
        raw_events.append({
            "ts": e["event_ts"],
            "machine": e["machine"],
            "category": e["event_type"],
            "description": _humanize(e["event_type"], e["description"], e["machine"]),
            "source": "ENDPOINT_LOG",
            "significance": _significance(e["event_type"]),
            "evidence_ids": _find_evidence_ids(evidence_list, e["machine"], e["event_type"]),
        })

    # Pull from network events
    for e in net_events:
        raw_events.append({
            "ts": e["event_ts"],
            "machine": f"{e['source_ip']} → {e['dest_ip']}",
            "category": "NETWORK_" + e["event_type"],
            "description": f"Network: {e['source_ip']} → {e['dest_ip']} port {e['port']} — {e['event_type']}",
            "source": "NETWORK_LOG",
            "significance": "HIGH",
            "evidence_ids": _eid_list(network_logs),
        })

    # Sort by timestamp
    raw_events.sort(key=lambda x: x["ts"])

    # Remove near-duplicates and build ordered list
    timeline = []
    seen_desc = set()
    order = 1
    for e in raw_events:
        key = (e["ts"][:16], e["category"])
        if key in seen_desc:
            continue
        seen_desc.add(key)

        db_manager.insert_timeline_event(
            e["ts"], order, e["machine"], e["category"],
            e["description"], e["evidence_ids"], e["significance"]
        )
        timeline.append({
            "order": order,
            "ts": e["ts"],
            "machine": e["machine"],
            "category": e["category"],
            "description": e["description"],
            "evidence_ids": e["evidence_ids"],
            "significance": e["significance"],
        })
        order += 1

    return timeline


def _humanize(event_type: str, description: str, machine: str) -> str:
    """Convert internal event types to investigator-readable descriptions."""
    mapping = {
        "INITIAL_COMPROMISE": f"🔴 Initial compromise detected on {machine}",
        "FILE_IMPACT": f"⚠️  File system modification detected on {machine}",
        "RANSOM_NOTE": f"📄 Ransomware-style note created on {machine}",
        "PROPAGATION": f"🌐 Simulated TCP/445 propagation attempt from {machine}",
        "PROPAGATED": f"🔴 {machine} compromised via simulated propagation",
        "HOST_COMPROMISED": f"🔴 Host compromised: {machine}",
        "INCIDENT_DECLARED": "🚨 CYBER INCIDENT DECLARED — threshold exceeded",
        "CONTAINMENT": f"🔒 {machine} isolated — network access blocked",
        "RECOVERY": f"✅ {machine} restored from clean baseline",
        "PROPAGATION_BLOCKED": f"🛡️  SECURITY CONTROL: Propagation blocked to {machine}",
        "AUTO_ISOLATED": f"🔒 {machine} automatically isolated by endpoint protection",
    }
    return mapping.get(event_type, description)


def _significance(event_type: str) -> str:
    high = {"INITIAL_COMPROMISE", "PROPAGATED", "HOST_COMPROMISED",
            "INCIDENT_DECLARED", "FILE_IMPACT", "RANSOM_NOTE", "PROPAGATION"}
    return "HIGH" if event_type in high else "MEDIUM"


def _find_evidence_ids(evidence_list, machine, event_type) -> str:
    """Find relevant evidence IDs for a given event."""
    ids = []
    type_map = {
        "INITIAL_COMPROMISE": "INFECTION_MARKER",
        "RANSOM_NOTE": "RANSOM_NOTE",
        "FILE_IMPACT": "AFFECTED_FILE",
    }
    target_type = type_map.get(event_type)
    for e in evidence_list:
        if target_type and e["evidence_type"] == target_type:
            if machine == "ALL" or e["machine"] == machine:
                ids.append(e["evidence_id"])
    endpoint_logs = [e["evidence_id"] for e in evidence_list
                     if e["evidence_type"] == "ENDPOINT_LOG"]
    ids.extend(endpoint_logs)
    return ", ".join(ids[:4]) if ids else ""


def _eid_list(ev_list) -> str:
    return ", ".join(e["evidence_id"] for e in ev_list[:2])


def build_investigation_summary() -> dict:
    """Build the final investigation findings summary."""
    machine_states = db_manager.get_machine_states()
    file_impacts = db_manager.get_file_impacts()
    net_events = db_manager.get_network_events()
    evidence_list = db_manager.get_evidence()

    compromised = [m for m, s in machine_states.items() if s["state"] in
                   ("COMPROMISED", "ISOLATED", "RECOVERING", "RECOVERED")]
    affected_files = [f for f in file_impacts if ".WCRY_SIMULATED" in f.get("affected_name", "")]
    smb_events = [e for e in net_events if e["port"] == 445]
    ransom_notes = [e for e in evidence_list if e["evidence_type"] == "RANSOM_NOTE"]

    return {
        "initial_host": db_manager.get_case_meta("patient_zero", "HOSPITAL-PC-01"),
        "affected_hosts": len(compromised),
        "affected_host_list": compromised,
        "total_affected_files": len(affected_files),
        "primary_file_indicator": ".WCRY_SIMULATED",
        "network_indicator": f"Synthetic TCP/445 SMB propagation ({len(smb_events)} events)",
        "ransomware_indicator": "WANNACRY_SIMULATION_NOTE.txt",
        "ransom_note_count": len(ransom_notes),
        "smb_event_count": len(smb_events),
        "evidence_count": len(evidence_list),
        "attack_start": db_manager.get_case_meta("attack_start_ts", "—"),
        "incident_declared": db_manager.get_case_meta("incident_declared_ts", "—"),
        "attack_sequence": [
            "Initial compromise (simulated dropper execution)",
            "File system impact (.WCRY_SIMULATED extension)",
            "Ransomware-style note creation",
            "Simulated TCP/445 worm propagation",
            "Additional host compromise (PC-02, PC-03)",
            "Multi-host file impact",
            "Incident declared",
        ],
        "attribution": (
            "Attribution not established by this laboratory evidence. "
            "Historical context: WannaCry (2017) attributed to Lazarus Group "
            "(DPRK) by multiple intelligence agencies — however this simulation "
            "does not replicate attribution forensics."
        ),
    }
