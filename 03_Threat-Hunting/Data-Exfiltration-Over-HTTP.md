# Data Exfiltration over HTTP(S) (Hunt & Runbook)
**File:** `/SOC-Runbook-Library/03_Threat-Hunting/Data-Exfiltration-Over-HTTP.md`  
**Author:** Javon McCloud  
**Maintainer:** McCloudSrAI  
**Version:** 1.0  
**MITRE Technique(s):** T1041 (Exfiltration Over C2 Channel), T1567 (Exfiltration Over Web Services)  
**Framework:** Threat Hunting / Detection Engineering (Hunt → Validate → Contain → Recover)

---

## 1️⃣ Scenario
A host or service is suspected of sending large volumes of data or sensitive files to an external HTTP(S) destination — either via large uploads, repeated POSTs, or uncommon endpoints for that host.

---

## 2️⃣ Data Sources & Detection Surface
- `DeviceNetworkEvents` (Outbound bytes, HTTP method, user-agent)  
- `CommonSecurityLog` (Proxy/firewall logs with request URL and bytes)  
- `DnsEvents` (domain lookups preceding upload)  
- (Optional) DLP events or cloud storage audit logs

---

## 3️⃣ Triage Steps
- Aggregate outbound bytes by host→destination over a window to find spikes or unusually large transfers.  
- Identify HTTP methods (POST/PUT) and content-types (multipart, application/zip, etc.).  
- Correlate originating process and account to determine legitimacy.  
- Enrich destination (WHOIS, ASN, TI) and verify whether destination is a known collaboration service.

Example KQL to find large outbound transfers:
```
let window = 24h;
CommonSecurityLog
| where TimeGenerated > ago(window)
| where DeviceAction =~ "allowed"
| summarize BytesOut=sum(toint(ReceivedBytes)), Hits=count() by SourceIP, DestinationIP, DestinationPort, URL
| where BytesOut > 20000000
| order by BytesOut desc
```

---

## 4️⃣ Containment
- Block the destination IP/domain at perimeter devices and in proxy/NGFW.  
- Isolate the host if active exfiltration is ongoing.  
- Revoke or rotate credentials/tokens used by the process if authenticated uploads are observed.

Containment actions should be coordinated with business owners to prevent disrupting legitimate transfers (backups, cloud sync).

---

## 5️⃣ Eradication & Recovery
- Capture forensic artifacts (PCAP if available, process dumps, browser histories).  
- Remove any malware or scripts facilitating exfiltration.  
- Restore host from known-good image when integrity is uncertain.  
- Engage data owners and legal/privcomms if sensitive data is confirmed exfiltrated.

---

## 6️⃣ Documentation & Escalation
- Document byte counts, URLs, timestamps, process names, and user accounts.  
- Escalate to IR and Data Loss Prevention teams when data sensitivity or business impact is high.  
- Preserve logs and evidence for potential legal or compliance review.

Critical attachments: `CommonSecurityLog` exports, `DeviceNetworkEvents` query results, and TI enrichment snapshots.

---

## 7️⃣ Automation Potential / Playbooks
- Logic App: threshold-based alert → enrich destination, notify SOC + DLP, create incident ticket.  
- Function App: continuous adaptive baseline for outbound bytes per host to detect deviations.  
- Automated blocklist updater to push confirmed malicious destinations to perimeter devices.

---

## 8️⃣ Tuning & Controls
- Establish baselines for expected outbound volumes per business unit and service.  
- Create allowlists for legitimate cloud services (AzureBlob, AWS S3, Box, Dropbox, etc.).  
- Integrate with DLP for content-aware detection and automated quarantine where supported.

---

