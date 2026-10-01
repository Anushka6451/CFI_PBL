"""
Logic test script — run from WannaCry_Forensic_Lab/ directory.
Tests all backend modules without GUI.
"""
import sys, shutil
sys.path.insert(0, '.')

print("Testing database...")
from database import db_manager
db_manager.initialize_database()
db_manager.reset_database()
print("  OK")

print("Testing hospital environment...")
from simulation.hospital_environment import (
    create_hospital_environment, capture_baseline, MACHINES
)
created = create_hospital_environment()
print(f"  Created {len(created)} files  OK")

records = capture_baseline()
print(f"  Baseline: {len(records)} files hashed  OK")

print("Testing simulation...")
from simulation.incident_simulator import run_full_simulation
events = run_full_simulation()
print(f"  Simulation: {len(events)} events generated  OK")

print("Testing forensics — evidence...")
from forensics.evidence_collector import collect_all_evidence
evidence = collect_all_evidence()
print(f"  Evidence: {len(evidence)} items  OK")

print("Testing forensics — hashing...")
from forensics.hashing import verify_all_evidence
results = verify_all_evidence()
verified = sum(1 for r in results if r['status'] == 'VERIFIED')
print(f"  Hash verification: {verified}/{len(results)} verified  OK")

print("Testing forensics — file analysis...")
from forensics.file_analyzer import analyze_file_changes
fa = analyze_file_changes()
print(f"  File analysis: {fa['affected_count']} affected  OK")

print("Testing forensics — network analysis...")
from forensics.network_analyzer import analyze_smb_traffic
net = analyze_smb_traffic()
print(f"  Network: {net['smb_events']} SMB events  OK")

print("Testing forensics — timeline...")
from forensics.timeline import reconstruct_timeline, build_investigation_summary
timeline = reconstruct_timeline()
print(f"  Timeline: {len(timeline)} events reconstructed  OK")

summary = build_investigation_summary()
print(f"  Summary: {summary['affected_hosts']} hosts, {summary['total_affected_files']} files  OK")

print("Testing containment & recovery...")
from simulation.recovery import contain_all_machines, recover_all_machines
contain_all_machines()
print("  Containment  OK")
recover_all_machines()
print("  Recovery  OK")

# Cleanup
shutil.rmtree('simulation_lab', ignore_errors=True)

print()
print("=" * 40)
print("  ALL BACKEND TESTS PASSED")
print("=" * 40)
