import csv
import hashlib
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
REPORTS = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def read_csv(name):
    with (EVIDENCE / name).open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

events = read_csv("windows_events.csv")
network = read_csv("network_log.csv")
iocs = read_csv("iocs.csv")

evidence_files = sorted(p for p in EVIDENCE.iterdir() if p.is_file())
hashes = {p.name: sha256(p) for p in evidence_files}

suspicious_event_ids = {"7045", "4688", "4663"}
suspicious_events = [e for e in events if e["event_id"] in suspicious_event_ids]
smb = [n for n in network if n["port"] == "445"]

host_counter = Counter()
for n in smb:
    host_counter[n["source"]] += 1

affected_hosts = sorted(set(
    [e["host"] for e in events if e["event_id"] in {"4663", "1001"}]
    + [n["source"] for n in smb]
    + [n["destination"] for n in smb if n["destination"].startswith("WS-")]
))

first_event = min(events, key=lambda x: x["timestamp"])["timestamp"]
last_event = max(events, key=lambda x: x["timestamp"])["timestamp"]

report = []
report.append("CYBER TERRORISM CASE STUDY INVESTIGATION")
report.append("=" * 50)
report.append("Case ID: CT-2017-WCRY-SIM-001")
report.append("Case: Simulated WannaCry-style ransomware incident")
report.append("Classification: Educational cyber-forensics simulation")
report.append("")
report.append("1. EXECUTIVE SUMMARY")
report.append("-" * 25)
report.append(
    "The simulated investigation identified suspicious process/service activity, "
    "repeated internal SMB traffic on TCP/445, rapid file modification, and simulated "
    "ransomware-note artifacts. These findings support a ransomware-style propagation "
    "scenario. The evidence is synthetic and is not a forensic conclusion about a real victim."
)
report.append("")
report.append("2. EVIDENCE INVENTORY AND HASHES")
report.append("-" * 35)
for name, digest in hashes.items():
    report.append(f"{name}: SHA-256 {digest}")

report.append("")
report.append("3. KEY DIGITAL EVIDENCE")
report.append("-" * 25)
report.append(f"Windows event records: {len(events)}")
report.append(f"Suspicious event records: {len(suspicious_events)}")
report.append(f"Network records: {len(network)}")
report.append(f"SMB/TCP-445 records: {len(smb)}")
report.append(f"IOC definitions: {len(iocs)}")
report.append("Artifacts: ransom_note.txt, unknown.exe (simulated reference)")

report.append("")
report.append("4. TIMELINE")
report.append("-" * 12)
for e in events:
    report.append(
        f'{e["timestamp"]} | {e["host"]} | Event {e["event_id"]} | {e["description"]}'
    )

report.append("")
report.append("5. NETWORK ANALYSIS")
report.append("-" * 22)
for host, count in host_counter.items():
    report.append(f"{host}: {count} SMB connection(s)")
report.append(
    "Repeated TCP/445 connections between internal hosts are treated as a propagation "
    "indicator in this simulation."
)

report.append("")
report.append("6. IOC ANALYSIS")
report.append("-" * 16)
for i in iocs:
    report.append(f'{i["type"]}: {i["value"]} — {i["description"]}')

report.append("")
report.append("7. IMPACT ASSESSMENT")
report.append("-" * 22)
report.append(f"Potentially affected hosts observed in evidence: {len(affected_hosts)}")
report.append("Observed effects: suspicious execution, service creation, SMB propagation, mass file modification, ransom-note detection.")
report.append("Business impact: simulated loss of workstation/file availability.")

report.append("")
report.append("8. FORENSIC INTERPRETATION")
report.append("-" * 28)
report.append(
    "The evidence forms a consistent simulated sequence: suspicious activity on WS-01, "
    "internal SMB connections, suspicious execution on additional hosts, mass file "
    "modification, and ransom-note artifacts. Further real-world attribution would require "
    "additional validated evidence such as packet captures, malware samples, memory images, "
    "authenticated log sources, and external threat-intelligence correlation."
)

report.append("")
report.append("9. CHAIN OF CUSTODY")
report.append("-" * 20)
report.append("Evidence ID: EV-SIM-001")
report.append("Collector: Student Investigator")
report.append("Acquisition: Simulated evidence package")
report.append("Integrity: SHA-256 values recorded above")
report.append("Handling: Analyze copies; preserve original evidence")

report.append("")
report.append("10. RECOMMENDATIONS")
report.append("-" * 20)
for item in [
    "Patch vulnerable systems and maintain a vulnerability-management process.",
    "Segment critical systems and restrict unnecessary SMB traffic.",
    "Maintain tested offline/immutable backups.",
    "Deploy endpoint detection and centralized logging.",
    "Preserve volatile evidence before shutting down systems when appropriate.",
    "Document chain of custody and evidence hashes.",
    "Prepare and regularly test an incident-response plan."
]:
    report.append(f"- {item}")

report.append("")
report.append("11. CONCLUSION")
report.append("-" * 14)
report.append(
    "This practical demonstrates the core workflow of a cyber-forensics investigation: "
    "identify evidence, verify integrity, analyze host and network artifacts, reconstruct "
    "a timeline, identify IOCs, assess impact, and document findings."
)

output = REPORTS / "case_analysis_report.txt"
output.write_text("\n".join(report), encoding="utf-8")

print("\n=== CYBER FORENSICS INVESTIGATION COMPLETE ===")
print(f"Case ID: CT-2017-WCRY-SIM-001")
print(f"Evidence files analyzed: {len(evidence_files)}")
print(f"Suspicious events: {len(suspicious_events)}")
print(f"SMB records: {len(smb)}")
print(f"Timeline: {first_event} -> {last_event}")
print(f"Report: {output}")
print("\nSHA-256 evidence hashes:")
for name, digest in hashes.items():
    print(f"  {name}: {digest}")
