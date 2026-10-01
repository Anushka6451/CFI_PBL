# Cyber Terrorism Case Study Investigation — Real-Time Forensic Simulation

A safe academic prototype that demonstrates how investigators could analyze a destructive cyber incident affecting critical infrastructure. The case is inspired by the **23 December 2015 Ukraine electric power grid cyberattack** and maps reconstructed events to publicly documented behaviors. It runs on the Python standard library only.

> **Safety:** This project contains no malware, exploit code, credential theft logic, scanning, persistence, destructive commands, or real attacker infrastructure. Every IP address, username, log line, hash, and timestamp used in the simulation is synthetic. `198.51.100.0/24` is documentation address space.

## What the application demonstrates

- Real-time event streaming using Python's built-in HTTP server + Server-Sent Events (SSE)
- Historical incident context and attack-stage visualization
- Synthetic phishing, endpoint, VPN, remote-access, ICS/HMI, telephony, and disk telemetry
- Evidence acquisition as events arrive
- Chain-of-custody tracking with simulated integrity/hash records
- MITRE ATT&CK technique mapping
- Dynamic risk score and critical-alert counters
- Downloadable JSON case export
- Responsive browser interface; no frontend build tools required

## Historical case basis

Public sources describe the 2015 attack as a coordinated disruption of Ukrainian electricity distribution. MITRE ATT&CK documents spearphishing, BlackEnergy, credential collection, valid-account/remote-service access, remote control-system interaction, breaker manipulation, and destructive KillDisk behavior associated with the campaign. U.S. government reporting states that three distribution companies experienced outages affecting roughly 225,000 customers for about 1–6 hours.

The academic label **“cyber terrorism”** is debated. This project does not make a legal classification; it uses the event as a critical-infrastructure cyber-incident case study suitable for forensic-investigation coursework.

## Project structure

```text
cyber_terrorism_case_study/
├── app.py
├── requirements.txt
├── README.md
├── CASE_STUDY_REPORT.md
├── run_windows.bat
├── run_linux_mac.sh
├── data/
│   └── incident.json
├── templates/
│   └── index.html
├── static/
│   ├── css/style.css
│   └── js/app.js
└── tests/
    └── test_app.py
```

## Run on Windows

```powershell
cd cyber_terrorism_case_study
python app.py
```

Then open: `http://127.0.0.1:5000`

You can also double-click `run_windows.bat` after Python is installed.

## Run on Linux/macOS

```bash
cd cyber_terrorism_case_study
python3 app.py
```

Then open: `http://127.0.0.1:5000`

## How to demonstrate the aim

1. Open the dashboard.
2. Click **Start simulation**.
3. Watch the reconstructed attack progress from phishing to destructive impact.
4. Observe evidence cards unlocking as each digital artifact is identified.
5. Explain how each artifact supports or challenges the incident hypothesis.
6. Review the chain-of-custody table to show preservation and integrity tracking.
7. Export the case JSON for submission or further analysis.

## Evidence included

- `EV-001` suspicious spearphishing email/header
- `EV-002` Office child-process execution telemetry
- `EV-003` credential-capture behavior alert
- `EV-004` abnormal VPN authentication
- `EV-005` remote administration session toward an HMI
- `EV-006` unauthorized breaker-open HMI audit events
- `EV-007` call-center denial-of-service pattern
- `EV-008` destructive disk-wipe alert

## Tests

```bash
python -m unittest discover -s tests -v
```

## Sources

- MITRE ATT&CK, *2015 Ukraine Electric Power Attack (C0028)*: https://attack.mitre.org/campaigns/C0028/
- CISA, *Understanding and Mitigating Russian State-Sponsored Cyber Threats to U.S. Critical Infrastructure*: https://www.cisa.gov/news-events/alerts/2022/01/11/understanding-and-mitigating-russian-state-sponsored-cyber-threats-us-critical-infrastructure
- SANS ICS, *Confirmation of a Coordinated Attack on the Ukrainian Power Grid*: https://www.sans.org/blog/confirmation-of-a-coordinated-attack-on-the-ukrainian-power-grid

## Educational use

Designed for cyber forensics, incident response, digital evidence, ICS-security, and case-study demonstrations. Extend it with additional **synthetic** evidence sources, investigator notes, evidence tagging, or report generation without adding live offensive capability.
