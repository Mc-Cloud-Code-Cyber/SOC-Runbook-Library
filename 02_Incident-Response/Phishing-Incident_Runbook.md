# Phishing Incident Runbook
**File:** `/SOC-Runbook-Library/02_Incident-Response/Phishing-Incident_Runbook.md`  
**Author:** Javon McCloud  
**Maintainer:** McCloudSrAI  
**Version:** 1.0  
**MITRE ID(s):** T1566 – Phishing, T1078 – Valid Accounts (if credential theft)  
**Framework:** NIST SP 800-61 (Detection → Containment → Eradication → Recovery)

---

## 1️⃣ Scenario
A user reports a suspicious email or Defender for Office 365 / Sentinel flags an email containing credential harvesting links or malicious attachments. Potential outcomes include credential compromise, malware installation, or lateral phishing spread.

---

## 2️⃣ Detection Source
- Microsoft Defender for Office 365 (phish/malware detections)  
- Sentinel tables: `EmailEvents`, `OfficeActivity`, `SecurityAlert`  
- Exchange Online Protection (EOP) logs

---

## 3️⃣ Triage Steps
- Pull the message trace and full email headers. Identify sender, sender IP, SPF/DKIM/DMARC status, and delivery path.  
- Extract URLs and attachment hashes; query threat intel (VirusTotal, MS TI).  
- Determine scope: which mailboxes received the message? Were any users who clicked or opened it identified?

KQL examples:
```
EmailEvents
| where TimeGenerated > ago(7d)
| where SenderFromAddress has "suspiciousdomain.com" or ThreatTypes has_any ("Phish","Malware")
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, Subject, Urls, AttachmentNames, ThreatTypes
| top 100 by TimeGenerated
```

Enrichment:
- Check for user clicks via `OfficeActivity` or Defender click reports.
- Correlate with `SigninLogs` for subsequent suspicious sign-ins from recipients.

---

## 4️⃣ Containment
- **Quarantine** the message and remove from all mailboxes (tenant-wide sweep).  
- **Block sender domain/IP** at mail-flow and/or perimeter.  
- If credentials are suspected compromised: **disable affected accounts**, require password reset and MFA re-registration.

Containment play:
- Execute Exchange `New-ComplianceSearch` / `New-ComplianceSearchAction` (or EOP bulk removal) to purge messages.
- Notify impacted users and SOC.

---

## 5️⃣ Eradication & Recovery
- Remove all copies of the phish from mailboxes.  
- If malware delivered, follow Malware Execution Runbook for infected endpoints.  
- Reset credentials for impacted users; enforce conditional access or step-up auth if needed.  
- Run phishing awareness communication; provide the targeted users with remediation steps.

Recovery validation:
- Monitor for failed/suspicious logins for 30 days.  
- Check for any lateral distribution (internal forwarded copies).

---

## 6️⃣ Documentation & Escalation
- Record full email headers, message trace, KQL outputs, user interview notes, and remediation actions.  
- Escalate to Incident Response / Threat Intelligence if: credential theft confirmed, malware payload executed, or campaign scope is broad.

Required documentation to attach:
- Message EML or header, attachment hash, URL screenshots, and timeline.

---

## 7️⃣ Automation Potential
- **Logic App:** Trigger on Sentinel phish analytic rule → quarantine message (Graph API/EOP), notify SOC, create ticket.  
- **Automated Response Script (PowerShell):** Search and purge messages, add blocking transport rules, and log actions in an audit table.

---

## 8️⃣ Lessons & Tuning
- Create detection for similar sender patterns, reply-chain anomalies, and atypical internal->external forwarding.  
- Enhance mail flow rules and implement DMARC quarantine policies if not already enforced.  
- Run phishing tabletop and improve user reporting mechanism (one-click reporting to SOC).

---

