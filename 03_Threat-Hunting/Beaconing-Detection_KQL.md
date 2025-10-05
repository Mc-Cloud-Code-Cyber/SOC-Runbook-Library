
# 🛰️ Beaconing Detection (KQL Hunt)
**Directory:** `/SOC-Runbook-Library/03_Threat-Hunting/`  
**Author:** Javon McCloud  
**Maintainer:** McCloudSrAI  
**Version:** 1.0  
**MITRE Technique(s):** T1071 (Application Layer Protocol), T1095 (Non-Application Layer Protocol)  
**Data Sources:** `DnsEvents`, `DeviceNetworkEvents`, `CommonSecurityLog`

---

## 🎯 Objective
Identify hosts that exhibit **periodic outbound communications** (beaconing) with low jitter, small payloads, or regular time intervals — indicators of potential Command & Control (C2) traffic.

---

## 🧪 Hunt 1 — DNS Beaconing
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

## 🧪 Hunt 2 — Network Beaconing by IP/Port
```
let window = 24h;
DeviceNetworkEvents
| where TimeGenerated > ago(window)
| where RemotePort in (80,443,8080,8443)
| summarize Times=make_list(TimeGenerated), Count=count(), BytesOut=sum(OutboundBytes)
  by DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, InitiatingProcessFileName
| where Count > 10
| extend Times=array_sort(Times)
| extend Deltas=array_zip(Times[1..], Times[..array_length(Times)-2])
| extend Deltas=array_map(x: datetime_diff('minute', tostring(parse_json(x)[0]), tostring(parse_json(x)[1])), Deltas)
| extend MeanDelta=todouble(array_avg(Deltas)), Stdev=todouble(array_stdev(Deltas))
| where MeanDelta between (3.0 .. 90.0) and Stdev < 6.0
| project DeviceName, User=InitiatingProcessAccountName, Process=InitiatingProcessFileName, Remote= strcat(RemoteIP, ":", tostring(RemotePort)), Hits=Count, MeanInterval_Min=MeanDelta, Jitter=Stdev
| order by Hits desc
```

---

## 🧪 Hunt 3 — Beaconing via Proxy/Firewall Logs
```
let window = 24h;
CommonSecurityLog
| where TimeGenerated > ago(window)
| where DeviceAction =~ "allowed"
| summarize Times=make_list(TimeGenerated), Count=count(), BytesSent=sum(toint(ReceivedBytes))
  by SourceIP, DestinationIP, DestinationPort, RequestURL
| where Count > 10
| extend Times=array_sort(Times)
| extend Deltas=array_zip(Times[1..], Times[..array_length(Times)-2])
| extend Deltas=array_map(x: datetime_diff('minute', tostring(parse_json(x)[0]), tostring(parse_json(x)[1])), Deltas)
| extend MeanDelta=todouble(array_avg(Deltas)), Stdev=todouble(array_stdev(Deltas))
| where MeanDelta between (3.0 .. 120.0) and Stdev < 8.0
| project SourceIP, Destination= strcat(DestinationIP, ":", tostring(DestinationPort)), URL=RequestURL, Hits=Count, BytesSent, MeanInterval_Min=MeanDelta, Jitter=Stdev
```

---

## ✅ Validation & Next Steps
- Pivot to host telemetry: identify process initiating beacon.  
- Enrich remote IP/domain with TI feeds (VirusTotal, GreyNoise, WHOIS).  
- Compare beacon intervals with known RAT/C2 patterns.  

---

## ⚙️ Automation Ideas
- Logic App: on match → enrich IOC + notify via Teams.  
- Function App: calculate periodicity score for new network destinations.  

---

### 💬 “Every beacon is a whisper — find who’s calling home.”
