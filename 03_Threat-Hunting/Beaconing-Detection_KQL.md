# Beaconing Detection (Threat Hunt / Runbook)
**File:** `/SOC-Runbook-Library/03_Threat-Hunting/Beaconing-Detection_KQL.md`  
**Author:** Javon McCloud  
**Maintainer:** McCloudSrAI  
**Version:** 1.0  
**MITRE Technique(s):** T1071 (Application Layer Protocol), T1095 (Non-Application Layer Protocol)  
**Framework:** Threat Hunting / Detection Engineering (Hunt → Validate → Contain → Remediate)

---

## 1️⃣ Scenario
Hosts are observed performing periodic outbound communications (DNS or HTTP/HTTPS) to a small set of destinations with regular timing (low jitter) — behavior consistent with beaconing used by C2 frameworks or automated tooling.

---

## 2️⃣ Data Sources & Detection Surface
- `DnsEvents` (DNS query cadence)  
- `DeviceNetworkEvents` (remote IP/port, HTTP/HTTPS metadata)  
- `CommonSecurityLog` (proxy/firewall logs)  
- (Optional) JA3/JA3S, TLS metadata, and threat intel feeds

---

## 3️⃣ Triage Steps
- Run periodicity KQLs (see hunts) to surface candidate host→destination pairs.  
- Confirm the process and user context via `DeviceProcessEvents` / `DeviceInfo`.  
- Enrich destination IP/FQDN (VirusTotal, GreyNoise, WHOIS, ASN).  
- Verify whether destination is a known management/monitoring service (RMM, backups, CDNs).

KQL (example hunt to find regular DNS queries):
```
let window = 24h;
let min_hits = 10;
DnsEvents
| where TimeGenerated > ago(window)
| project TimeGenerated, ClientIP, QueryName
| summarize Times=make_list(TimeGenerated), Count=count() by ClientIP, QueryName
| where Count >= min_hits
| extend Times = array_sort(Times)
| extend Deltas = array_zip(Times[1..], Times[..array_length(Times)-2])
| extend Deltas = array_map(x: datetime_diff('minute', tostring(parse_json(x)[0]), tostring(parse_json(x)[1])), Deltas)
| extend MeanDelta = todouble(array_avg(Deltas)), StdevDelta = todouble(array_stdev(Deltas))
| where MeanDelta between (5.0 .. 60.0) and StdevDelta < 4.0
| project ClientIP, QueryName, Hits=Count, MeanInterval_Min=MeanDelta, Jitter=StdevDelta
| order by Hits desc
```

---

## 4️⃣ Containment
- If confirmed malicious: isolate the host via EDR (Defender for Endpoint) to stop further egress.  
- Block destination IP/FQDN at perimeter (FW/proxy) and on NGFW/IDS.  
- If beaconing is tied to an account/service: disable associated credentials or revoke tokens.

Containment must be coordinated with application owners — watch for false positives from legitimate scheduled tasks or monitoring systems.

---

## 5️⃣ Eradication & Recovery
- Collect forensic artifacts (process list, memory image, autoruns, scheduled tasks) before remediation.  
- Remove persistence (services, scheduled tasks, startup entries) and delete malicious binaries.  
- Reimage host when integrity cannot be ensured.  
- Rotate credentials and keys if credential theft is suspected.  
- Increase monitoring of the host and related accounts for 30 days post-recovery.

---

## 6️⃣ Documentation & Escalation
- Create incident ticket with: hunt query outputs, enriched destination details, process lineage, and timeline.  
- Tag priority based on destination reputation and presence of lateral movement or data access.  
- Escalate to IR / Threat Hunting for full forensics when: multiple hosts beacon to same destination, evidence of data staging/exfiltration, or confirmed persistence.

Required evidence: `DeviceNetworkEvents` and `DeviceProcessEvents` exports, DNS query lists, and TI enrichment snapshots.

---

## 7️⃣ Automation Potential / Playbooks
- Logic App: on hunt match → enrich IOC (VT, GreyNoise) → create incident + post summary to Teams.  
- Function App: implement periodicity scoring to score and persist suspect destinations for trend analysis.  
- Automated blocklist updater: push confirmed malicious IPs/FQDNs to perimeter devices and EDR.

---

## 8️⃣ Tuning & Lessons
- Build allowlists for known monitoring platforms and RMM tools.  
- Tune `min_hits`, `window`, and jitter thresholds for your environment to reduce false positives.  
- Add process/signature-based filters (e.g., known-signed management binaries) to reduce noise.

---
