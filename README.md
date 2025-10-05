# 🛡️ SOC Runbook Library

### Author: Javon McCloud | Security & Threat Analyst | SOC Engineer  
> Designed and maintained by **McCloudSrAI** — enterprise-grade operational framework for security operations, incident response, and detection engineering.

---

## 📖 Overview

The **SOC Runbook Library** is a structured collection of operational playbooks and response procedures engineered for use in a **Security Operations Center (SOC)**.  
It demonstrates the ability to standardize incident handling, streamline triage, and align security operations with frameworks such as **MITRE ATT&CK**, **NIST 800-61**, and **CIS Controls**.

This project is part of a broader goal to simulate real-world SOC workflows using **Microsoft Sentinel**, **Microsoft Defender**, and custom automation scripts.  
Each runbook includes detection logic, triage steps, containment actions, and automation opportunities — showcasing end-to-end **Incident Response (IR) lifecycle management**.

---

## 🧱 Project Structure

```
/SOC-Runbook-Library
  
├── 01_Alert-Triage/  
│   ├── Sentinel_Initial_Alert_Review.md  
│   ├── Suspicious_Login_Event.md  
│   ├── Malicious_Email_Detected.md
    
├── 02_Incident-Response/  
│   ├── Phishing-Incident_Runbook.md  
│   ├── Malware-Execution_Runbook.md  
│   ├── Privilege-Escalation_Runbook.md
  
├── 03_Threat-Hunting/  
│   ├── Beaconing-Detection_KQL.md  
│   ├── PowerShell-Command-Logging_KQL.md  
│   ├── Data-Exfiltration-Over-HTTP.md  
  
├── 04_Automation-Playbooks/  
│   ├── Auto-Isolate-Device_LogicApp.json  
│   ├── Disable-User-Account_PowerShell.ps1  
│   ├── Alert-Enrichment_FunctionApp.py  
  
├── 05_Reporting-And-Metrics/  
│   ├── Daily-SOC-Metrics-Workbook.json  
│   ├── Incident-Closure-Report_Template.md  
  
└── README.md  
```

---

## ⚔️ Purpose & Objectives

This repository serves three core objectives:

1. **Demonstrate Operational Maturity**  
   - Showcase structured incident response workflows modeled after enterprise SOC practices.  
   - Reinforce repeatability and standardization in security operations.

2. **Develop Detection & Response Skills**  
   - Apply Microsoft Sentinel KQL queries for detection and triage.  
   - Integrate Microsoft Defender and Azure automation for containment.

3. **Bridge Manual & Automated IR Workflows**  
   - Translate manual Tier-1/Tier-2 playbooks into Logic App or PowerShell automation.  
   - Build foundations for SOAR (Security Orchestration, Automation & Response).

---

## 🧩 Runbook Format

All runbooks follow a **7-section template** for consistency and clarity:

| Section | Description |
|----------|--------------|
| **1. Scenario Description** | High-level overview of the alert or threat scenario. |
| **2. Detection Source** | Log source and analytic rule within Microsoft Sentinel. |
| **3. Triage Steps** | Validation steps, enrichment, and contextual investigation using KQL. |
| **4. Containment Actions** | Steps to limit impact — host isolation, account disablement, etc. |
| **5. Eradication & Recovery** | Long-term remediation or patching steps. |
| **6. Documentation & Escalation** | Incident ticketing, notes, and escalation chain. |
| **7. Automation Potential** | Logic App, PowerShell, or API integrations to automate repetitive steps. |

---

## 🧠 Framework Alignment

- **MITRE ATT&CK:** Maps each runbook to relevant Tactics/Techniques (e.g., T1078, T1059).  
- **NIST SP 800-61 Rev. 2:** Aligns with IR lifecycle (Preparation → Detection → Containment → Recovery → Lessons Learned).  
- **CIS Control 17:** Establishes incident response management and testing processes.

---

## 🚀 How to Use

1. **Deploy Microsoft Sentinel** with connected data sources (Defender for Endpoint, Azure AD, O365).  
2. **Clone this repository** into your SOC documentation workspace:  
   <<<bash
   git clone https://github.com/Mc-Cloud-Code-Cyber/SOC-Runbook-Library.git
   <<<
3. **Start with `01_Alert-Triage/`** to learn how alerts are validated and escalated.  
4. Follow linked **KQL queries** and **automation scripts** for hands-on replication in your lab.  
5. Use `05_Reporting-And-Metrics/` to visualize SOC performance metrics in Sentinel workbooks.

---

## 🧰 Tools & Technologies

- **Microsoft Sentinel (SIEM)**
- **Microsoft Defender for Endpoint / Identity / Cloud Apps**
- **Azure Logic Apps & Function Apps**
- **PowerShell 5.1+ / Python 3.10+**
- **GitHub Markdown Documentation**
- **MITRE ATT&CK Navigator**

---

## 📈 Future Enhancements

- Add **playbook integrations** (Defender to Sentinel via Logic Apps).  
- Include **incident simulation datasets** for red-blue team testing.  
- Build a **custom SOC dashboard** using Sentinel Workbooks.  
- Integrate **threat intelligence enrichment** (VirusTotal, MISP, GreyNoise).  
- Publish **incident response metrics** via Power BI or Azure Workbook.

---

## 🤝 Contribution Guidelines

This project is open for professional collaboration and skill demonstration.  
If you would like to contribute a runbook, ensure it includes:

- Clear detection logic (KQL or tool-based)  
- Mapped MITRE ATT&CK technique(s)  
- Containment & recovery actions  
- Automation potential notes  

Submit via pull request or contact the repository maintainer.

---

## 🏁 License

This repository is released under the [MIT License](LICENSE).  
Use, adapt, and expand these frameworks for personal or organizational SOC development.

---

### 💬 “A mature SOC isn’t built by tools alone — it’s built by process.”
