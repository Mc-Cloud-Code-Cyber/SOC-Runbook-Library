# Privilege Escalation Runbook
**File:** `/SOC-Runbook-Library/02_Incident-Response/Privilege-Escalation_Runbook.md`  
**Author:** Javon McCloud  
**Maintainer:** McCloudSrAI  
**Version:** 1.0  
**MITRE ID(s):** T1068 (Exploitation for Privilege Escalation), T1078 (Valid Accounts)  
**Framework:** NIST SP 800-61 (Detection → Analysis → Containment → Recovery)

---

## 1️⃣ Scenario
Detections or alerts indicate a user or process received elevated privileges (new local admin, service token use, or suspicious creation of admin-equivalent accounts). Examples: unexpected addition to local Administrators, Service Account misuse, or exploitation patterns that lead to higher privileges.

---

## 2️⃣ Detection Source
- Windows Security Events (`SecurityEvent` in Sentinel): Event IDs like **4728/4729/4732/4733** (group membership changes), **4672** (special privileges assigned), **4624** (logon) correlated with suspicious behavior.  
- Sentinel tables: `SecurityEvent`, `AuditLogs`, `DeviceProcessEvents`, `AADAuditLogs`, `IdentityInfo`  
- Sysmon events (if available) for process lineage

---

## 3️⃣ Triage Steps
- Identify the user or account that gained privilege and the mechanism (group add, service modification, token manipulation).  
- Retrieve who performed the change (source admin account, automated system, or possible compromise).  
- Assess if changes were legitimate (helpdesk ticket, scheduled maintenance).

KQL examples:
```
SecurityEvent
| where EventID in (4728, 4732, 4729, 4733, 4672)
| project TimeGenerated, Computer, Account, TargetAccount, SubjectAccount, EventID, RenderedDescription
| sort by TimeGenerated desc
```

Correlate:
- Cross-check `AADAuditLogs` for matching group changes in Azure AD.  
- Check `DeviceProcessEvents` for suspicious processes that may have performed the change.

---

## 4️⃣ Containment
- If change is unauthorized: **remove account from privileged group** and **disable the offending account** used to perform the change.  
- Temporarily disable service accounts showing unusual activity.  
- Block any session tokens or reset service credentials as needed.

Containment steps must be coordinated with identity owners to avoid business disruption.

---

## 5️⃣ Eradication & Recovery
- Investigate root cause (credential theft, exploited vulnerability, automation misconfiguration).  
- Revoke sessions and reset passwords/keys for compromised accounts.  
- Rebuild or reconfigure any compromised service accounts.  
- Restore least privilege and review group membership for drift.

Recovery actions:
- Re-install or reconfigure services if escalated by malicious actor.  
- Implement additional controls (Just-In-Time admin, Privileged Access Workstations, conditional access).

---

## 6️⃣ Documentation & Escalation
- Document timeline, responsible principals, method of elevation, and impacted assets.  
- Escalate to IAM/Identity Security and IR team for a post-incident privileged access review.  
- Preserve logs and evidence for forensic analysis.

Key evidence:
- Event logs with EventIDs and correlation IDs, account change tickets, and process lineage.

---

## 7️⃣ Automation Potential
- **Logic App:** Detect group membership changes → alert IAM team and automatically create a remediation task if the change is from an unexpected source.  
- **Scripted Playbook (PowerShell/Graph API):** Revoke group membership, rotate credentials for service accounts, and log remediation actions.

---

## 8️⃣ Tuning & Controls
- Implement alerting for any privileged group changes not tied to a ticketed change window.  
- Enforce Just-In-Time privilege elevation and break-glass auditing.  
- Harden monitoring on sensitive accounts and enable MFA + conditional access for privilege elevation paths.

---

