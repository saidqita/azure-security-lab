# Azure Cloud Security Lab — Microsoft Sentinel SIEM & Incident Response

A hands-on cloud security lab built in Microsoft Azure, simulating a real enterprise SOC environment. This project covers the full detection lifecycle: environment hardening → attack simulation → detection engineering → incident investigation → MITRE ATT&CK mapping.

---

## What Was Built

A virtualized enterprise environment in Azure consisting of:

- **2 Virtual Machines** — a Windows Server 2022 target and an Ubuntu 24.04 attacker
- **Microsoft Sentinel** — cloud-native SIEM connected to a Log Analytics Workspace
- **Microsoft Entra ID** — identity management with a least-privilege SOC Analyst account
- **Network Security Groups** — hardened inbound rules following least-privilege principles
- **3 Custom KQL Analytics Rules** — detecting brute-force, lateral movement, and cross-plane anomalies
- **End-to-end Incident Investigation** — triaged in Sentinel and mapped to MITRE ATT&CK

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SecurityLab-RG                        │
│                                                          │
│   ┌──────────────────┐      ┌──────────────────┐        │
│   │  WinVM-Target    │      │  LinuxVM-Attacker │        │
│   │  Windows 2022    │◄─────│  Ubuntu 24.04    │        │
│   │  RDP: 3389 open  │      │  Hydra brute-    │        │
│   │  SSH: 3389 deny  │      │  force tool      │        │
│   └────────┬─────────┘      └──────────────────┘        │
│            │ Security Events (AMA agent)                 │
│            ▼                                             │
│   ┌──────────────────────────────────────────┐          │
│   │       Log Analytics Workspace             │          │
│   │       SecurityLab-Workspace               │          │
│   └──────────────────┬───────────────────────┘          │
│                      │                                   │
│                      ▼                                   │
│   ┌──────────────────────────────────────────┐          │
│   │         Microsoft Sentinel (SIEM)         │          │
│   │   Analytics Rules │ Incidents │ KQL Logs  │          │
│   └──────────────────────────────────────────┘          │
│                                                          │
│   ┌──────────────────────────────────────────┐          │
│   │         Microsoft Entra ID                │          │
│   │   SOC Analyst account (Security Reader)   │          │
│   └──────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────┘
```

---

## Phase 1 — Environment Setup

### Resources Provisioned

| Resource | Name | Purpose |
|---|---|---|
| Resource Group | SecurityLab-RG | Container for all lab resources |
| Log Analytics Workspace | SecurityLab-Workspace | Central log aggregation |
| SIEM | Microsoft Sentinel | Threat detection and investigation |
| Windows VM | WinVM-Target | Attack target (Windows Server 2022) |
| Linux VM | LinuxVM-Attacker | Attack source (Ubuntu 24.04) |
| Entra ID User | soc-analyst@[tenant] | Least-privilege SOC account |

### Security Hardening Applied

**Network Security Group rules on WinVM-Target:**
- RDP (3389) — Allow inbound (intentional for simulation)
- SSH (22) — Explicit Deny at priority 100 (least-privilege: Windows has no use for SSH)
- All other inbound — Default deny at priority 65500

**Entra ID RBAC:**
- Created dedicated `SOC Analyst` user account
- Assigned `Security Reader` role scoped to SecurityLab-RG
- Security Reader allows read access to security data without the ability to modify resources or configurations — principle of least privilege applied to identity

**Data Collection:**
- Windows Security Events connector configured via Azure Monitor Agent (AMA)
- Data collection rule set to ingest `AllEvents` from WinVM-Target into the Log Analytics Workspace

---

## Phase 2 — Brute-Force Attack Simulation

**Tool used:** [Hydra](https://github.com/vanhauser-thc/thc-hydra) — industry-standard penetration testing credential attack tool

**Attack type:** Dictionary attack against RDP (port 3389) targeting the `labadmin` account

**Command used:**
```bash
hydra -l labadmin -P passwords.txt rdp://[TARGET_IP] -t 1 -W 3
```

**Result:** Multiple failed login attempts generated `EventID 4625` (An account failed to log on) in the Windows Security Event log, which flowed into Sentinel via the AMA data connector.

**Verification KQL query:**
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| project TimeGenerated, Account, IpAddress, LogonTypeName, Activity
| order by TimeGenerated desc
```

---

## Phase 3 — KQL Analytics Rules

Three scheduled analytics rules were authored in Microsoft Sentinel. Full KQL is in the [`/kql-rules`](./kql-rules/) folder.

### Rule 1 — Brute Force Detection
**File:** [`kql-rules/brute-force-detection.kql`](./kql-rules/brute-force-detection.kql)

Detects when an account experiences more than 5 failed RDP login attempts within a 5-minute window. Fires a High severity alert mapped to MITRE ATT&CK T1110.

### Rule 2 — Lateral Movement Detection
**File:** [`kql-rules/lateral-movement-detection.kql`](./kql-rules/lateral-movement-detection.kql)

Detects a successful RDP logon (EventID 4624, Logon Type 10) that follows multiple failed attempts from the same source IP, indicating credential compromise followed by lateral movement. Mapped to T1021.001.

### Rule 3 — Entra ID & Host Event Correlation
**File:** [`kql-rules/entra-host-correlation.kql`](./kql-rules/entra-host-correlation.kql)

Correlates Microsoft Entra ID sign-in failures with host-level Windows Security Event failures from the same IP address. Provides cross-plane visibility linking cloud identity attacks with on-host activity.

> **Note:** Entra ID sign-in log streaming requires an Entra ID P1/P2 license, which is not included in the Azure free tier. This rule was written and deployed — in a production environment it would provide full cloud-to-host correlation.

---

## Phase 4 — Incident Investigation

After the analytics rules triggered, the generated incident was investigated end-to-end inside Microsoft Sentinel:

1. Opened the incident in the Sentinel Incidents dashboard
2. Used the **Investigation Graph** to visualise entity relationships (account → IP → alerts)
3. Reviewed the **Timeline** to establish chronological attack sequence
4. Ran manual KQL queries to enumerate all related events
5. Mapped observed activity to MITRE ATT&CK framework
6. Documented findings in a structured Incident Response report

### MITRE ATT&CK Mapping

| Technique ID | Name | Observed Activity |
|---|---|---|
| T1110 | Brute Force | Hydra cycled credentials against RDP — multiple EventID 4625 in rapid succession |
| T1110.001 | Password Guessing | Dictionary wordlist used — classic guessing attack against known username |
| T1021 | Remote Services | RDP used as the remote access vector for both attack and simulated lateral movement |
| T1021.001 | Remote Desktop Protocol | EventID 4624 Logon Type 10 (RemoteInteractive) detected following failed attempts |

Full incident response report: [`incident-report/INC-001-report.md`](./incident-report/INC-001-report.md)

---

## Tools & Technologies

| Category | Tool / Service |
|---|---|
| Cloud Platform | Microsoft Azure |
| SIEM | Microsoft Sentinel |
| Identity | Microsoft Entra ID (formerly Azure AD) |
| Query Language | KQL (Kusto Query Language) |
| Attack Simulation | Hydra (THC) |
| Log Storage | Azure Log Analytics Workspace |
| Agent | Azure Monitor Agent (AMA) |
| Threat Framework | MITRE ATT&CK |

---

## Key Learnings

- How Azure Monitor Agent (AMA) collects and forwards Windows Security Events to a Log Analytics Workspace
- Writing KQL detection logic using `summarize`, `bin`, `join`, and `make_set` operators
- The difference between EventID 4624 (successful logon) and 4625 (failed logon) and their forensic significance
- How RBAC least-privilege applies to both network (NSG rules) and identity (Entra ID roles)
- How Sentinel correlates alerts into incidents and how the investigation graph maps entity relationships
- Practical understanding of MITRE ATT&CK technique classification in a real detection context

---

## Repository Structure

```
azure-sentinel-security-lab/
├── README.md
├── kql-rules/
│   ├── brute-force-detection.kql
│   ├── lateral-movement-detection.kql
│   └── entra-host-correlation.kql
├── incident-report/
│   └── INC-001-report.md
└── screenshots/
    └── (add your own screenshots here)
```

---

## Author

Built as part of a personal cybersecurity portfolio while studying **Nätverk, infrastruktur och cybersäkerhet** at Jönköping University.
