<div align="center">

# 🔍 LummaC2 Threat Hunting Lab – Hypothesis-Driven Threat Hunt Using Microsoft Sentinel & Sysmon

![Domain](https://img.shields.io/badge/Type-Hypothesis%20Driven%20Threat%20Hunting-darkred?style=for-the-badge)
![Platform](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-blue?style=for-the-badge)
![Advisory](https://img.shields.io/badge/CISA-AA25--141b-red?style=for-the-badge)

<img src="https://img.shields.io/badge/Simulation-LummaC2.exe%20(Safe)-green?style=flat-square" />
<img src="https://img.shields.io/badge/Telemetry-Sysmon%20v15.21-blue?style=flat-square" />
<img src="https://img.shields.io/badge/Hunt%201-3%20Results%20Confirmed-brightgreen?style=flat-square" />
<img src="https://img.shields.io/badge/IOC-94.158.244.69%20Detected-orange?style=flat-square" />
<img src="https://img.shields.io/badge/KQL%20Hunts-5%20Queries-purple?style=flat-square" />
<img src="https://img.shields.io/badge/MITRE-T1036%20%7C%20T1105%20%7C%20T1071-critical?style=flat-square" />

---

**Prepared by:** Bikash Raya
**Project Type:** Hypothesis-Driven Threat Hunting — CISA Advisory AA25-141b (LummaC2 / Lumma Stealer)

</div>

---

## 📁 Repository Structure

| File | Description |
| --- | --- |
| [LummaC2_Threat_Hunting_Lab_Report.pdf](./LummaC2_Threat_Hunting_Lab_Report.pdf) | Complete lab report with all screenshots embedded |
| README.md | Project overview |

---

## 📋 Overview

This lab demonstrates a complete **hypothesis-driven threat hunting** workflow using **Microsoft Sentinel**, **Sysmon v15.21**, and **KQL**, aligned with the CISA cybersecurity advisory:

> **AA25-141b — "Threat Actors Deploy LummaC2 Malware to Exfiltrate Sensitive Data from Organizations"**
> https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141b

The lab follows the full threat hunting lifecycle:

* 🧠 **Hypothesis** — What if LummaC2 was executed in this environment? How would I detect it?
* 🛠️ **Simulation** — Created a safe `LummaC2.exe` (launches only calc.exe) to generate named IOC telemetry
* 🔬 **Telemetry** — Installed Sysmon v15.21 to capture process creation, network, DNS, DLL loads
* 📡 **Ingestion** — Created a custom DCR to send Sysmon logs to Microsoft Sentinel
* 🔍 **Hunt** — Wrote 5 KQL queries mapped to CISA advisory indicators and MITRE ATT&CK techniques
* ✅ **Findings** — Hunt 1 confirmed 3 results, IOC hunt confirmed 1 result, Hunts 2-5 no results (expected)

> **⚠️ Disclaimer:** `LummaC2.exe` contains NO malicious functionality. It is a PowerShell script compiled to an executable that only launches `calc.exe`. It was intentionally named to simulate a known IOC filename for detection engineering and hunting validation purposes only.

---

## 🛠️ Technologies Used

* Microsoft Sentinel (Logs / KQL Hunting)
* Microsoft Defender XDR (security.microsoft.com)
* Sysmon v15.21 (Microsoft Sysinternals)
* PS2EXE (PowerShell to EXE compiler)
* Azure Data Collection Rule (Custom Windows Logs)
* Log Analytics Workspace (Bik-SOC-Lab)
* KQL (Kusto Query Language)
* CISA Advisory AA25-141b
* MITRE ATT&CK Framework
* any.run (IOC research)
* Windows Server 2022 (Web01)

---

## 🧪 Lab Environment

| Component | Value |
| --- | --- |
| Host VM | Web01 -- Windows Server 2022 (Public IP: 20.5.48.127) |
| Log Analytics Workspace | Bik-SOC-Lab |
| SIEM | Microsoft Sentinel |
| Endpoint Monitor | Sysmon v15.21 |
| DCR | Sysmon-DCR -- Microsoft-Windows-Sysmon/Operational!* |
| Simulation File | LummaC2.exe (safe -- PS2EXE compiled, launches calc.exe only) |
| IOC IP Simulated | 94.158.244.69 (nslookup from Web01) |

---

## 🦠 Threat Context — LummaC2 / Lumma Stealer

LummaC2 (Lumma Stealer) is an information-stealing malware sold as **Malware-as-a-Service (MaaS)**, first observed in August 2022. It targets cryptocurrency wallets, browser credentials, login data, and sensitive files.

| Property | Detail |
| --- | --- |
| Also Known As | Lumma Stealer \| LummaC2 Stealer |
| Type | Information Stealer (MaaS) |
| Origin | ex-USSR |
| First Seen | August 1, 2022 |
| Notable DLLs | `iphlpapi.dll` (IP Helper API) \| `winhttp.dll` (Windows HTTP Services) |
| C2 Method | Web-based Command & Control |
| Delivery | Phishing, Masquerading, Ingress Tool Transfer |

### MITRE ATT&CK Techniques (CISA Advisory)

| Technique | Name | Tactic |
| --- | --- | --- |
| T1566 | Phishing | Initial Access |
| T1036 | Masquerading | Defense Evasion |
| T1217 | Browser Information Discovery | Discovery |
| T1119 | Automated Collection | Collection |
| T1102 | Web Service (C2) | Command & Control |
| T1105 | Ingress Tool Transfer | Command & Control |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |

---

## 🧠 Hunting Hypothesis

> *"LummaC2-like activity may have executed in the environment. The goal of this hunt is to identify suspicious execution, DLL loading, network activity, DNS lookups, and possible download or transfer behavior related to LummaC2 tradecraft."*

---

## 🔬 Lab Phases

### Phase 1 — LummaC2 Simulation

Created a safe PowerShell script and compiled it to `LummaC2.exe` using PS2EXE:

**File: `LummaStealer_Simulation.ps1`**
```powershell
Write-Output "Lumma Stealer Simulation Started"
Start-Process calc.exe
Write-Output "Simulation Complete"
```

**Compile to EXE:**
```powershell
Install-Module PS2EXE -Scope CurrentUser
Import-Module PS2EXE
Invoke-PS2EXE `
  -InputFile  .\LummaStealer_Simulation.ps1 `
  -OutputFile .\LummaC2.exe
```

**Execute:**
```powershell
.\LummaC2.exe
```

✅ `LummaC2.exe` executed, `calc.exe` launched as child process, Sysmon Event ID 1 generated.

---

### Phase 2 — Sysmon Installation

```powershell
cd C:\Users\bikashsoc1\Downloads\Sysmon
.\Sysmon64.exe -accepteula -i
```

**Verify:**
```powershell
Get-Service Sysmon64
# Status: Running | Name: Sysmon64
```

**Sysmon Event IDs monitored:**

| Event ID | Description |
| --- | --- |
| 1 | Process Creation |
| 3 | Network Connection |
| 7 | Image Loaded (DLL) |
| 11 | File Creation |
| 13 | Registry Modification |
| 22 | DNS Query |

---

### Phase 3 — Ingest Sysmon Logs into Sentinel

Created a new Data Collection Rule:

| Setting | Value |
| --- | --- |
| DCR Name | Sysmon-DCR |
| Log Source | Custom Windows Logs: `Microsoft-Windows-Sysmon/Operational!*` |
| Target | Bik-SOC-Lab (Log Analytics Workspace) |

**Verify in Sentinel:**
```kql
Event
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| take 20
```
✅ 13+ results confirmed from Web01.

---

### Phase 4 — IOC Simulation (nslookup)

Simulated LummaC2 network activity by running nslookup against a known IOC IP:

```cmd
nslookup 94.158.244.69
# Resolves to: no-rdns.mivocloud.com
```

This generated a Sysmon Event ID 1 for `nslookup.exe` containing the IOC IP in the command line — detectable via Sentinel KQL.

---

## 🔍 KQL Threat Hunting Queries

### Hunt 1 — LummaC2 Process Execution (Simulated IOC)
```kql
Event
| where TimeGenerated > ago(24h)
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| where RenderedDescription has_any ("LummaC2.exe")
| project
    TimeGenerated,
    Computer,
    SysmonEventID = EventID,
    Activity = "LummaC2 Simulation Process Execution",
    RenderedDescription
| order by TimeGenerated desc
```
✅ **3 results confirmed** — LummaC2.exe process creation on Web01 with full telemetry.

---

### IOC Investigation Hunt — 94.158.244.69
```kql
Event
| where TimeGenerated > ago(24h)
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where RenderedDescription contains "94.158.244.69"
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc
```
✅ **1 result confirmed** — `nslookup.exe` (C:\Windows\System32\nslookup.exe) with IOC IP captured.

---

### Hunt 2 — Sysmon DLL Image Load (iphlpapi.dll / winhttp.dll)
```kql
Event
| where TimeGenerated > ago(24h)
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 7
| where RenderedDescription contains "iphlpapi.dll"
    or RenderedDescription contains "winhttp.dll"
| project TimeGenerated, Computer, RenderedDescription
| order by TimeGenerated desc
```
⬜ No results — expected (simulation does not load these DLLs).

---

### Hunt 3 — Suspicious Network / C2 Activity
```kql
Event
| where TimeGenerated > ago(24h)
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 3
| where RenderedDescription contains "LummaC2.exe"
| project TimeGenerated, Computer, RenderedDescription
| order by TimeGenerated desc
```
⬜ No results — expected (simulation makes no network connections).

---

### Hunt 4 — DNS Query for LummaC2 C2 Domains
```kql
let LummaDomains = dynamic([
    "blast-hubs.com",
    "blastikcn.com",
    "friendseforever.help",
    "shiningrstars.help",
    "generalmills.pro",
    "hoyoverse.blog"
]);
Event
| where TimeGenerated > ago(24h)
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 22
| where RenderedDescription has_any (LummaDomains)
| project TimeGenerated, Computer, RenderedDescription
| order by TimeGenerated desc
```
⬜ No results — expected (no C2 DNS queries in simulation).

---

### Hunt 5 — Suspicious Download / Transfer Activity
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where CommandLine has_any (
    "Invoke-WebRequest", "curl", "wget", "bitsadmin", "certutil"
  )
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine
| order by TimeGenerated desc
```
⬜ No results — expected (no download tools used in simulation).

---

## 📊 Hunt Results Summary

| Hunt | Description | Sysmon Event | MITRE | Result |
| --- | --- | --- | --- | --- |
| 1 | LummaC2.exe Process Execution | Event ID 1 | T1036 | ✅ 3 results |
| IOC | nslookup 94.158.244.69 | Event ID 1 | T1046 | ✅ 1 result |
| 2 | DLL Load (iphlpapi / winhttp) | Event ID 7 | T1574 | ⬜ No results (expected) |
| 3 | Network / C2 Activity | Event ID 3 | T1071 | ⬜ No results (expected) |
| 4 | DNS Query LummaC2 Domains | Event ID 22 | T1071 | ⬜ No results (expected) |
| 5 | Download Tool Usage | Event ID 4688 | T1105 | ⬜ No results (expected) |

> Hunts 2–5 returned no results because the simulation only generates process creation events. In a **real LummaC2 infection**, these queries would surface DLL loads, C2 beaconing, DNS lookups to malicious domains, and staged payload downloads — providing complete detection coverage aligned with the CISA advisory.

---

## 🎯 Skills Demonstrated

* Hypothesis-Driven Threat Hunting Methodology
* CISA Advisory-Based IOC Research & Analysis
* Sysmon Installation, Configuration & Log Verification
* Custom DCR for Sysmon Log Ingestion into Sentinel
* PS2EXE Simulation Engineering (Safe Malware Simulation)
* KQL Advanced Hunting Queries (5 hunt queries)
* IOC Investigation (nslookup / IP-based hunting)
* MITRE ATT&CK Technique Mapping (T1036, T1105, T1071, T1574)
* Microsoft Sentinel Log Analysis & Hunting
* KQL Detection Query Writing for Sysmon Event IDs 1, 3, 7, 22 (queries written; Event ID 1 results confirmed)
* Detection Engineering Validation
* Endpoint Telemetry Analysis (Sysmon Event ID 1 -- Process Creation confirmed)

---

## 🎯 Key Takeaway

> This lab demonstrates practical, hands-on threat hunting experience using Microsoft Sentinel and Sysmon — following a hypothesis-driven methodology aligned with the CISA advisory AA25-141b on LummaC2 malware. A safe simulation executable (LummaC2.exe) was created to generate realistic endpoint telemetry under a known IOC filename, Sysmon was deployed for deep endpoint visibility, and 5 KQL hunting queries were written and executed against real CISA advisory indicators. Hunt 1 confirmed 3 LummaC2.exe process creation events, and the IOC investigation hunt confirmed nslookup activity against IP 94.158.244.69 — demonstrating how a SOC analyst would detect this threat in a real environment.

---

## 🔗 Related Projects

> Part of the **Bikash Security Lab** series:
> * [Microsoft Sentinel & Defender XDR — SOC IR Lab](https://github.com/Bikash-Raya/Sentinel-Defender-XDR-SOC-Incident-Response-lab)
> * [Microsoft Sentinel — GeoIP Watchlist & Attack Map](https://github.com/Bikash-Raya/microsoft-sentinel-geoip-watchlist-attack-map)

---

## 🔗 Connect With Me

<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/bikash-raya/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=for-the-badge&logo=github)](https://github.com/Bikash-Raya)

</div>

---

<div align="center">

⭐ If you find this project useful, feel free to star the repository ⭐

</div>
