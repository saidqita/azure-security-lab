# Incident Response Report — INC-001

## Incident Summary

| Field | Value |
|---|---|
| **Incident ID** | INC-001 |
| **Severity** | High |
| **Status** | Resolved |
| **Detection Source** | Microsoft Sentinel — Brute Force Detection Analytics Rule |
| **Date/Time Detected** | [Timestamp from Sentinel incident] |
| **Date/Time Resolved** | [Timestamp when lab simulation ended] |
| **Analyst** | [Your name] |

---

## Affected Assets

| Asset | Detail |
|---|---|
| Target VM | WinVM-Target |
| Public IP | 20.166.59.176 |
| Private IP | 10.0.0.4 |
| Operating System | Windows Server 2022 Datacenter |
| Targeted Account | labadmin |

---

## Attack Source

| Field | Detail |
|---|---|
| Attacker VM | LinuxVM-Attacker |
| Attacker IP | [IP of LinuxVM-Attacker] |
| Tool Used | Hydra (THC) — credential brute-force tool |
| Attack Vector | RDP (TCP port 3389) |
| Method | Dictionary attack using wordlist of common passwords |

---

## Timeline of Events

| Time | Event | EventID | Notes |
|---|---|---|---|
| T+00:00 | First failed RDP login attempt detected | 4625 | Hydra begins wordlist iteration |
| T+00:XX | Failed attempts continue in rapid succession | 4625 | Multiple attempts per minute |
| T+00:XX | Sentinel analytics rule threshold exceeded | — | Rule fires after 5+ failures in 5 min window |
| T+00:XX | Sentinel alert generated | — | High severity alert created |
| T+00:XX | Incident created in Sentinel | — | Automatically correlated from alert |
| T+00:XX | Last failed attempt logged | 4625 | Hydra wordlist exhausted |
| T+00:XX | [If applicable] Successful logon detected | 4624 | Logon Type 10 (RemoteInteractive) |

> Fill in actual timestamps from your Sentinel KQL results using this query:
> ```kql
> SecurityEvent
> | where EventID in (4625, 4624)
> | where Account contains "labadmin"
> | project TimeGenerated, EventID, Activity, Account, IpAddress, LogonTypeName
> | order by TimeGenerated asc
> ```

---

## Detection Details

**KQL query that confirmed the attack:**
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| project TimeGenerated, Account, IpAddress, LogonTypeName, Activity
| order by TimeGenerated desc
```

**Results summary:**
- Total failed attempts: [count from your query]
- Source IP: [LinuxVM-Attacker IP]
- Target account: labadmin
- Logon type: 3 (Network) or 10 (RemoteInteractive)
- Time window: [start time] to [end time]

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Evidence |
|---|---|---|---|
| T1110 | Brute Force | Credential Access | Hydra generated rapid sequential EventID 4625 failures against a single account |
| T1110.001 | Password Guessing | Credential Access | Dictionary wordlist of common passwords used — not credential stuffing or spraying |
| T1021 | Remote Services | Lateral Movement | RDP (port 3389) used as the remote access vector |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | EventID 4624 Logon Type 10 (RemoteInteractive) indicates RDP session establishment |

---

## Root Cause Analysis

The attack was made possible by the following conditions:

1. **RDP exposed directly to the internet** — Port 3389 was accessible from any public IP with no IP restriction on the NSG inbound rule
2. **No account lockout policy** — Windows did not lock the labadmin account after repeated failures, allowing unlimited attempts
3. **Weak credential set** — The target account used a predictable password format vulnerable to dictionary attack
4. **No MFA** — No multi-factor authentication was configured on the account

---

## Containment Actions Taken

- [x] Identified source IP of the attack via KQL query
- [x] Reviewed NSG rules — confirmed RDP was intentionally open for simulation purposes
- [x] Verified no unauthorised changes were made to the VM during the simulation
- [x] Confirmed no data exfiltration occurred (lab environment, no sensitive data)
- [ ] In a real incident: block source IP at NSG level immediately
- [ ] In a real incident: disable or reset compromised account

---

## Recommendations

### Immediate (P1)
1. **Disable direct internet-facing RDP** — Use Azure Bastion or a VPN gateway instead. RDP should never be exposed on a public IP without restriction.
2. **Enable account lockout policy** — Configure Group Policy to lock accounts after 5 failed attempts for 30 minutes.

### Short-term (P2)
3. **Enforce MFA on all accounts** — Particularly privileged accounts and any account with RDP access.
4. **Enable Just-In-Time VM Access** — Microsoft Defender for Cloud's JIT feature opens RDP only when requested, for a limited time window, from a specific IP.
5. **Restrict RDP by source IP** — If RDP must remain open, limit the NSG inbound rule to known IP ranges only.

### Long-term (P3)
6. **Deploy Privileged Identity Management (PIM)** — Require justification and approval for privileged role activation.
7. **Enable Entra ID Identity Protection** — Automated risk-based conditional access policies that block sign-ins from risky IPs.
8. **Configure UEBA in Sentinel** — User and Entity Behavior Analytics to baseline normal behaviour and flag anomalies automatically.

---

## Lessons Learned

- EventID 4625 is the primary indicator of brute-force activity on Windows systems. High volume from a single source IP within a short time window is a reliable detection signal.
- Correlating failed logons (4625) with successful logons (4624) from the same IP reveals whether a brute-force attack succeeded — this is critical for determining scope and containment urgency.
- The Sentinel Investigation Graph significantly accelerates triage by visualising entity relationships — in this case linking the source IP, target account, and triggered alerts into a single view.
- Mapping to MITRE ATT&CK during investigation ensures consistent classification and enables comparison against threat intelligence feeds.

---

*Report prepared as part of Azure Cloud Security Lab — personal cybersecurity portfolio project.*
