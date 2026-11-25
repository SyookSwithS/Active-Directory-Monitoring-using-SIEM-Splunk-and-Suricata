# Splunk Detection Queries (SPL)

All searches below were run against `index=main sourcetype="WinEventLog:Security"`, using **local Windows Event Log collection** directly on the Domain Controller (Splunk Enterprise was installed on the same host). No Splunk Add-on for Microsoft Windows was installed, so field names are the raw WinEventLog fields confirmed via `| table _time, *` rather than CIM-normalized fields (`src_ip`, `dest`, etc. did **not** work in this environment).

---

## 1. Verify log ingestion is working

```spl
index=* | stats count by index, sourcetype
```

## 2. Field discovery (run this before building any new detection)

```spl
index=main sourcetype="WinEventLog:Security" EventCode=<code>
| table _time, *
```

## 3. SMB / Credential Brute Force Detection (INC-002)

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Authentication_Package, Source_Network_Address, Workstation_Name
```

Confirmed working fields for EventCode 4625 in this environment: `Account_Name`, `Authentication_Package`, `Source_Network_Address` (not `src_ip`), `Workstation_Name`.

## 4. New User Account Created (INC-003)

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4720
| table _time, Account_Name, Caller_User_Name
```

## 5. User Added to Privileged Group — Domain Admins (INC-003)

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4728
| table _time, Account_Name, Group_Name
```

## 6. Scheduled Task Created — Persistence (INC-003)

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4698
| table _time, Account_Name, Task_Name
```

> **Known gap:** this search returned **0 events** until the `Other Object Access Events` audit subcategory was explicitly enabled via:
> ```powershell
> auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
> ```
> Default Windows audit policy does not capture this event category out of the box.

## 7. Combined Privilege Escalation / Persistence View (INC-003)

```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4728 OR EventCode=4698)
| table _time, EventCode, Account_Name, Group_Name, Task_Name
```

## 8. Windows Event Log Cleared — Anti-Forensics (INC-004)

```spl
index=main sourcetype="WinEventLog:Security" EventCode=1102
| table _time, Account_Name, Computer_Name
```

## 9. Confirm Pre-Clearing Evidence Survives in Splunk (INC-004 — closing check)

```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4728 OR EventCode=4698)
| table _time, EventCode, Account_Name, Computer_Name, Task_Name
```

Run this **after** a log-clearing event to confirm the SIEM retains evidence that no longer exists in the local Windows Event Viewer.

---

> **Tip:** Save any of these as a Splunk **Alert** (Save As → Alert) with a trigger condition (e.g. "number of results > 0") to simulate a real SOC correlation rule firing in production.
