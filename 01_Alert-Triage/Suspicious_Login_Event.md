
# 🌍 Suspicious Login Event Runbook
**Directory:** `/SOC-Runbook-Library/01_Alert-Triage/`  
**Author:** Javon McCloud  
**Maintainer:** McCloudSrAI  
**Version:** 1.0  
**MITRE ID:** T1078 – Valid Accounts  
**Framework:** NIST 800-61 (Detection → Containment)

---

## 1️⃣ Scenario
A Sentinel analytic rule flags a user login from an unrecognized IP address or unusual geographic region.

---

## 2️⃣ Detection Source
- Azure AD `SigninLogs`  
- Analytic Rule: *Unfamiliar Sign-in Properties*  

---

## 3️⃣ Triage Steps
<<<
SigninLogs
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Logins=count(), Locations=make_set(Country) by UserPrincipalName
<<<
- Compare user’s normal sign-in history and device.  
- Verify MFA success and check if device is compliant.  
- Run IP reputation lookup (VirusTotal, IPVoid, or OTX).  

---

## 4️⃣ Containment Actions
- Temporarily disable user account.  
- Revoke active sessions using Microsoft Graph API.  

---

## 5️⃣ Eradication & Recovery
- Force password reset and MFA re-registration.  
- Verify user’s physical location or travel.  

---

## 6️⃣ Documentation & Escalation
- Add screenshots of sign-in map or query output.  
- Escalate to Tier 2 if multiple users share same source IP.  

---

## 7️⃣ Automation Potential
- Logic App: trigger on alert → disable account + Teams notification.  
- Python Function: enrich IP data via GeoIP or threat intelligence API.  

---

### 💬 “Every unusual login is a question — your triage provides the answer.”
