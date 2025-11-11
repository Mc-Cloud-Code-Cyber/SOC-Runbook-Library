# ✉️ Malicious Email Detected Runbook
**Directory:** `/SOC-Runbook-Library/01_Alert-Triage/`  
**Author:** Javon McCloud  
**Maintainer:** McCloudSrAI  
**Version:** 1.0  
**MITRE ID:** T1566 – Phishing  
**Framework:** NIST 800-61 (Detection → Containment → Recovery)

---

## 1️⃣ Scenario
Microsoft Defender for Office 365 or Sentinel detects a potentially malicious email containing harmful URLs or attachments.

----

## 2️⃣ Detection Source
- Microsoft Defender for Office 365  
- Microsoft Sentinel → `EmailEvents`, `SecurityAlert`

---

## 3️⃣ Triage Steps
```
EmailEvents
| where ThreatTypes has_any ("Phish", "Malware")
| project TimeGenerated, SenderFromAddress, Subject, Urls, DeliveryLocation
```
- Review sender domain and SPF/DKIM results.  
- Check URL and attachment reputation (VirusTotal / Hybrid Analysis).  
- Search if message was delivered to multiple mailboxes.  

---

## 4️⃣ Containment Actions
- Quarantine the suspicious message.  
- Block sender domain and related IP addresses.  

---

## 5️⃣ Eradication & Recovery
- Purge all copies of message from tenant mailboxes.  
- Reset affected user credentials if link clicked.  
- Conduct awareness training refresh for user.  

---

## 6️⃣ Documentation & Escalation
- Update Sentinel incident with KQL and screenshots.  
- Escalate to Threat Hunting if campaign indicators found.  

---

## 7️⃣ Automation Potential
- Logic App: auto-quarantine flagged message + send Teams notification.  
- PowerShell: `Search-Mailbox` and `New-TransportRule` for bulk cleanup.  

---

### 💬 “Fast triage of one email can stop an entire campaign.”

