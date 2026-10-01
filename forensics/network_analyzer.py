"""
Network Analyzer — WannaCry Forensic Lab
Analyzes synthetic network traffic for forensic investigation.
"""

from database import db_manager
from simulation.hospital_environment import MACHINES


def get_all_traffic(port_filter=None, source_filter=None, dest_filter=None) -> list:
    """Return filtered network events."""
    events = db_manager.get_network_events()
    if port_filter:
        events = [e for e in events if str(e.get("port", "")) == str(port_filter)]
    if source_filter:
        events = [e for e in events if source_filter in e.get("source_ip", "")]
    if dest_filter:
        events = [e for e in events if dest_filter in e.get("dest_ip", "")]
    return events


def analyze_smb_traffic() -> dict:
    """Analyze SMB-specific traffic patterns."""
    all_events = db_manager.get_network_events()
    smb_events = [e for e in all_events if e.get("port") == 445]

    sources = set(e["source_ip"] for e in smb_events)
    destinations = set(e["dest_ip"] for e in smb_events)

    # Build IP → machine name map
    ip_map = {v["ip"]: f"{k} ({v['name']})" for k, v in MACHINES.items()}

    patterns = []
    for e in smb_events:
        patterns.append({
            "time": e["event_ts"],
            "source": ip_map.get(e["source_ip"], e["source_ip"]),
            "dest": ip_map.get(e["dest_ip"], e["dest_ip"]),
            "port": e["port"],
            "protocol": e["protocol"],
            "event_type": e["event_type"],
            "description": e["description"],
        })

    return {
        "total_events": len(all_events),
        "smb_events": len(smb_events),
        "smb_sources": [ip_map.get(ip, ip) for ip in sources],
        "smb_destinations": [ip_map.get(ip, ip) for ip in destinations],
        "smb_patterns": patterns,
        "finding": (
            f"{len(smb_events)} synthetic TCP/445 events detected originating "
            f"from {', '.join(sources)}. "
            "Repeated TCP/445 connections from a single host to multiple "
            "internal hosts is consistent with worm-style lateral movement. "
            "IMPORTANT NOTE: TCP/445 activity alone does not confirm WannaCry — "
            "this correlation requires supporting endpoint and file system evidence."
        ),
    }
