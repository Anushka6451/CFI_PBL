# Cyber Terrorism Case Study Investigation
## Case: 2015 Ukraine Electric Power Grid Cyberattack — Safe Forensic Reconstruction

### Aim
To analyze a real critical-infrastructure cyber incident, identify relevant categories of digital evidence, reconstruct a defensible incident timeline, map observed behavior to ATT&CK techniques, and demonstrate preservation through a real-time application prototype.

### Incident summary
On 23 December 2015, Ukrainian electricity distribution companies experienced coordinated cyber-enabled power outages. Public reporting describes a multi-stage intrusion that included spearphishing, BlackEnergy malware activity, credential compromise, remote access into operational environments, malicious use of control-system interfaces, and destructive actions that complicated restoration.

The historical facts are separated from the prototype evidence. The dashboard does **not** contain original victim logs. Instead, it creates synthetic forensic artifacts that reflect categories of evidence investigators would seek.

### Investigation hypothesis
An adversary first obtained an enterprise foothold through a malicious attachment, acquired operator credentials, used valid remote-access paths, pivoted toward the control environment, remotely manipulated HMI-controlled breakers, disrupted communications, and performed destructive cleanup activity to delay recovery.

### Digital evidence identified

| ID | Evidence | Investigative value |
|---|---|---|
| EV-001 | Mail gateway/header record | Establishes likely initial-access vector and delivery context |
| EV-002 | Endpoint process telemetry | Correlates document execution with suspicious child-process behavior |
| EV-003 | Credential-capture alert | Supports credential-theft hypothesis |
| EV-004 | VPN authentication log | Shows valid-account access from an unusual source |
| EV-005 | Remote-support audit | Connects enterprise/jump access to the HMI workstation |
| EV-006 | HMI/SCADA audit log | Links unauthorized cyber activity to breaker-open commands and physical impact |
| EV-007 | PBX/call-center metadata | Shows communications disruption during the outage window |
| EV-008 | Disk telemetry | Indicates destructive activity intended to hinder restoration and evidence collection |

### ATT&CK mapping
The prototype demonstrates or references the following behaviors: spearphishing attachment (`T1566.001`), Visual Basic/scripted execution (`T1059.005`), system-binary proxy execution (`T1218.011`), keylogging/input capture (`T1056.001`), ICS external remote services (`T0822`), ICS remote services (`T0886`), manipulation of control (`T0831`), and disk-structure wipe (`T1561.002`).

### Chain of custody
When an artifact is revealed by the simulation, the application records the evidence ID, acquisition event, a synthetic integrity/hash status, and a named custodian. In a real investigation this would be expanded to include acquisition tool/version, UTC timestamp, original media identifier, cryptographic hash, storage location, transfer history, examiner signatures, and authorization details.

### Prototype flow
1. Start simulation.
2. Events stream from the Python standard-library backend using Server-Sent Events.
3. Each incident event updates the live timeline, risk score, ATT&CK stage and alert count.
4. Associated evidence is unlocked in the evidence locker.
5. The corresponding chain-of-custody entry is created.
6. At completion, the investigator can review the reconstructed case and export the underlying JSON dataset.

### Safety and scope
No offensive payloads are implemented. The prototype does not send phishing messages, execute macros, harvest credentials, open network sessions, issue ICS commands, wipe disks, or perform denial-of-service activity. Its purpose is to demonstrate **forensic observation and analysis** of a reconstructed incident.

### Conclusion
The simulation demonstrates how evidence from email, endpoints, identity systems, remote-access infrastructure, industrial-control logs, telephony systems, and disk telemetry can be correlated into a coherent incident timeline. The strongest evidence of operational impact is the HMI audit trail showing unauthorized breaker commands correlated with the simulated outage, while VPN and remote-support logs help connect earlier credential compromise to control-system access.
