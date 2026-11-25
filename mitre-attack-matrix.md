# MITRE ATT&CK Mapping

| Stage | Tactic | Technique ID | Technique Name | Detected By | Incident |
|---|---|---|---|---|---|
| Nmap scan against Domain Controller | Reconnaissance | T1595 | Active Scanning | Security Onion (Suricata — ET SCAN signatures) | [INC-001](incidents/INC-001-reconnaissance.md) |
| SMB brute force (NetExec) | Credential Access | T1110 | Brute Force | Splunk (EventCode 4625) | [INC-002](incidents/INC-002-smb-bruteforce.md) |
| New domain account created | Persistence | T1136 | Create Account | Splunk (EventCode 4720) | [INC-003](incidents/INC-003-privilege-escalation.md) |
| Added to Domain Admins | Privilege Escalation | T1098 | Account Manipulation | Splunk (EventCode 4728) | [INC-003](incidents/INC-003-privilege-escalation.md) |
| Scheduled task persistence | Persistence | T1053.005 | Scheduled Task | Splunk (EventCode 4698) — required an audit policy fix first | [INC-003](incidents/INC-003-privilege-escalation.md) |
| Clear Windows Security Event Log | Defense Evasion | T1070.001 | Clear Windows Event Logs | Splunk (EventCode 1102) | [INC-004](incidents/INC-004-log-tampering.md) |

## Coverage Summary

| Attack Stage | Detected by Splunk (Host) | Detected by Security Onion (Network) |
|---|---|---|
| Reconnaissance (Nmap) | ❌ No native signal | ✅ Yes — ET SCAN Nmap/Terminal Server signatures |
| SMB Brute Force | ✅ Yes — EventCode 4625 | — (not checked in this lab run) |
| Privilege Escalation / Persistence | ✅ Yes — EventCode 4720/4728/4698 (after audit policy fix) | — (not checked in this lab run) |
| Log Tampering | ✅ Yes — EventCode 1102, plus pre-clearing evidence preserved | — (not checked in this lab run) |

This demonstrates why a mature SOC relies on both **SIEM** (host/application telemetry) and **NSM** (network telemetry) — neither alone has full visibility across the kill chain.
