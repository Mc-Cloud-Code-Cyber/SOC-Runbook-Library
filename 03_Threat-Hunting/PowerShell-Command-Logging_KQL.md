# PowerShell Command Logging (Hunt & Runbook)
**File:** `/SOC-Runbook-Library/03_Threat-Hunting/PowerShell-Command-Logging_KQL.md`  
**Author:** Javon McCloud  
**Maintainer:** McCloudSrAI  
**Version:** 1.0  
**MITRE Technique(s):** T1059.001 (PowerShell), T1027 (Obfuscation), T1105 (Ingress Tool Transfer)  
**Framework:** Threat Hunting / Detection Engineering (Hunt → Validate → Contain → Remediate)

---

## 1️⃣ Scenario
PowerShell is abused for script-based payload execution (encoded commands, web-based downloaders, AMSI bypasses, or LOLBin-based post-exploitation). Detecting obfuscated flags, suspicious parent/child relationships, and web retrieval patterns is critical.

---

## 2️⃣ Data Sources & Detection Surface
- `DeviceProcessEvents` (command-line visibility)  
- `DeviceEvents` (AMSI-related events, script content)  
- `SecurityEvent` / Sysmon (ProcessCreate events)  
- (Optional) EDR script capture, defender telemetry

---

## 3️⃣ Triage Steps
- Run KQL hunts to locate `-enc`, `-encodedcommand`, `IEX`, `DownloadString`, or `Bypass` usage.  
- Identify initiating parent process to detect phishing or document-based loaders.  
- Decode Base64 payloads for rapid review; capture decoded script content when available.  
- Correlate with network events for download URLs and subsequent connections.

Representative KQL to find encoded/obfuscated PowerShell usage:
```
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-enc","-encodedcommand","FromBase64String","IEX","DownloadString","Bypass","NoProfile","-nop")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName, ProcessCommandLine, ReportId
| order by TimeGenerated desc
```

---

## 4️⃣ Containment
- Immediately isolate the affected host if active malicious behavior or C2 is observed.  
- Kill malicious processes via EDR and prevent process restart.  
- Remove or disable compromised accounts if credential misuse is suspected.

Containment must include collecting volatile evidence (memory, running processes) prior to full remediation.

---

## 5️⃣ Eradication & Recovery
- Remove persistence items (scheduled tasks, Run keys, services) and delete malicious files.  
- Reimage if filesystem or memory integrity is in question.  
- Rotate any credentials or secrets that may have been exposed.  
- Run thorough AV/EDR scans and patch relevant software.

---

## 6️⃣ Documentation & Escalation
- Document decoded payloads, parent/child process trees, fetched URLs, and any file hashes.  
- Escalate to IR when evidence shows lateral movement, credential theft, or sensitive data access.  
- Attach AMSI/script content and KQL query outputs to the ticket.

Essential artifacts: decoded script(s), process tree export, `DeviceProcessEvents` query results, and network download evidence.

---

## 7️⃣ Automation Potential / Playbooks
- Logic App: on detection → fetch process snapshot, attempt automated Base64 decode, store decoded script in secure blob, notify SOC.  
- Function App: scheduled hunting job that decodes encoded payloads and flags known malicious patterns.  
- PowerShell remediation playbook (manual approval required) to remove persistence and collect forensic logs.

---

## 8️⃣ Tuning & Controls
- Create allowlists for signed administrative scripts and known tooling (Intune, SCCM, RMM).  
- Monitor for frequently abused parent processes (office apps, mshta, wscript) and create context-aware alerts.  
- Enforce AMSI and script block logging across endpoints for higher-fidelity telemetry.

---

