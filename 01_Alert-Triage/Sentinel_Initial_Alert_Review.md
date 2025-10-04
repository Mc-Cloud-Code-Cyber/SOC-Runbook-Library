# 🔎 Sentinel Initial Alert Review Runbook
**Directory:** `/SOC-Runbook-Library/01_Alert-Triage/`  
**Author:** Javon McCloud  
**Maintainer:** McCloudSrAI  
**Version:** 1.0  
**MITRE Alignment:** N/A – General Alert Triage  
**Framework:** NIST 800-61 (Detection → Analysis)

---

## 1️⃣ Scenario
A new alert appears in Microsoft Sentinel — analyst must determine whether it’s valid, benign, or false positive.

---

## 2️⃣ Detection Source
- Microsoft Sentinel Alert Queue  
- Tables: `SecurityAlert`, `Heartbeat`, `DeviceInfo`, `SigninLogs`

---

## 3️⃣ Triage Steps
```
SecurityAlert
| where TimeGenerated > ago(1d)
| project AlertName, Severity, ProviderName, CompromisedEntity, Tactics, TimeGenerated
```
- Review alert title, severity, and correlated entities.  
- Validate by cross-checking Defender alerts or sign-in logs.  
- Search historical alerts on same entity (user, IP, or host).  

---

## 4️⃣ Containment Actions
- If verified malicious: isolate host or disable account.  
- If uncertain: tag as *Under Investigation* and escalate.  

---

## 5️⃣ Eradication & Recovery
- Validate if related to larger campaign or recurring false positives.  
- Document and tune analytic rule if alert deemed non-malicious.  

---

## 6️⃣ Documentation & Escalation
- Record investigation notes and attached evidence.  
- Escalate to Tier 2 with full query context and alert JSON export.  

---

## 7️⃣ Automation Potential
- Logic App: parse new Sentinel alerts → enrich IPs + geo-location.  
- Function App: auto-assign incidents by entity type and severity.  

---

### 💬 “Consistent triage builds consistent defense.”

