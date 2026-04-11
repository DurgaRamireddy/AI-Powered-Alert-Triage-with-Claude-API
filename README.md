# AI-Powered Alert Triage with Claude API

**Tools:** Python 3 · Claude API (claude-opus-4-5) · Splunk Enterprise · Impacket · CrackMapExec · VMware Workstation · Ubuntu · Windows Server 2022 · Windows 10 · Kali Linux  
**MITRE ATT&CK:** T1558.003 · T1558.004 · T1021.002 · T1550.002  
**Type:** Home Lab · Blue Team · SOC Analysis · AI-Assisted Triage · SIEM · Threat Detection

> This project was independently designed and built as a personal home lab project, not part of coursework. All infrastructure, attack simulation, detection logic, and documentation were self-directed.

> ⚠️ **Disclaimer:** This project was conducted entirely in an isolated VMware lab environment for educational purposes only. No real systems, networks, or individuals were targeted. All IP addresses are private VMware addresses that exist solely within the local lab.

---

## Overview

This project builds an end-to-end AI-assisted SOC triage pipeline. Real attack-generated SIEM alerts from a home Active Directory lab are normalized, fed through the Claude API acting as a Tier 1 SOC analyst, and displayed in a custom analyst dashboard alongside manual triage for AI vs human comparison.

The goal was to answer a real SOC question: **can an AI model reliably triage SIEM alerts, and where does it fail?**

**What this project demonstrates end-to-end:**

1. Generate real SIEM alerts by running Kerberoasting, AS-REP Roasting, and lateral movement attacks against a live AD environment
2. Export and normalize 38 alerts from Splunk into a consistent JSON schema
3. Build a Python triage engine that calls the Claude API with a structured SOC analyst system prompt
4. Receive structured JSON triage output per alert - severity, verdict, MITRE mapping, escalation decision, evidence summary
5. Display AI triage alongside manual analyst triage in a custom dark-mode dashboard
6. Audit AI failure cases using deliberately degraded alerts and document where the model hallucinated

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    VMware Host-Only Network                     │
│                      192.168.255.0/24                           │
│                                                                 │
│  ┌──────────────────────┐      ┌──────────────────────────────┐ │
│  │  Windows Server 2022 │      │       Ubuntu 22.04           │ │
│  │  WIN-I4UHLQF702E     │      │   Splunk Enterprise 9.x      │ │
│  │  DC: lab.local       │      │   192.168.255.131            │ │
│  │  192.168.255.130     │      │   port 8000 (web)            │ │
│  │  AD DS / DNS / KDC   │      │   port 9997 (forwarder)      │ │
│  └──────────────────────┘      └──────────────────────────────┘ │
│            │                                 ▲                  │
│            │ Domain Auth                     │ Windows Logs     │
│            ▼                                 │                  │
│  ┌──────────────────────┐                    │                  │
│  │   Windows 10         │────────────────────┘                  │
│  │   DESKTOP-4FNNSE5    │  Universal Forwarder                  │
│  │   192.168.255.132    │                                       │
│  │   Corp-PC01          │                                       │
│  └──────────────────────┘                                       │
│                                                                 │
│  ┌──────────────────────┐                                       │
│  │   Kali Linux         │  Runs attacks → generates alerts      │
│  │   192.168.255.135    │  Impacket · CrackMapExec · BloodHound │
│  └──────────────────────┘                                       │
└─────────────────────────────────────────────────────────────────┘
                          │
                          │ Claude API (claude-opus-4.5)
                          ▼
              ┌───────────────────────┐
              │   Python Triage       │
              │   Engine              │
              │   triage_engine.py    │
              └───────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Analyst Dashboard   │
              │   dashboard.html      │
              │   AI vs Manual Triage │
              └───────────────────────┘
```

| VM | OS | IP | Role |
|---|---|---|---|
| WIN-I4UHLQF702E | Windows Server 2022 | 192.168.255.130 | Domain Controller (lab.local) |
| DESKTOP-4FNNSE5 | Windows 10 22H2 | 192.168.255.132 | Corp-PC01 (domain-joined) |
| Ubuntu VM | Ubuntu 22.04 | 192.168.255.131 | Splunk Enterprise Server |
| Kali Linux | Kali Rolling | 192.168.255.135 | Attacker Machine |

**Domain:** `lab.local`  
**Domain Users:** `jsmith` (standard user), `mjones` (standard user), `Administrator` (domain admin)

---

## Phase 1 - Attack Simulation & Alert Generation

### Attacks Executed from Kali Linux

```bash
# Kerberoasting - requests RC4-encrypted TGS tickets for user SPNs
python3 GetUserSPNs.py LAB.local/jsmith:Password \
  -dc-ip 192.168.255.130 -request

# AS-REP Roasting - targets accounts without Kerberos pre-auth
python3 GetNPUsers.py LAB.local/ \
  -usersfile /etc/passwd -dc-ip 192.168.255.130

# Lateral Movement - SMB network logons via CrackMapExec
crackmapexec smb 192.168.255.130 192.168.255.132 \
  -u jsmith -p Password
```

### Splunk Alert Counts

| Attack | Event Code | Alerts Generated |
|---|---|---|
| Kerberoasting | 4769 | 18 |
| AS-REP Roasting | 4768 | 7 |
| Lateral Movement (SMB) | 4624 | 13 |
| **Total** | | **38** |

### SPL Queries Used

```spl
-- Kerberoasting detection
index=* EventCode=4769
| table _time, ComputerName, Account_Name, Service_Name,
        Client_Address, Ticket_Encryption_Type

-- AS-REP Roasting detection
index=* EventCode=4768
| table _time, ComputerName, Account_Name, Client_Address,
        Status, Pre_Authentication_Type

-- Lateral Movement detection
index=* EventCode=4624 Logon_Type=3 Account_Name=jsmith
| table _time, ComputerName, Account_Name, Logon_Type,
        Workstation_Name, IpAddress
```

---

## Phase 2 - Alert Normalization

All 38 alerts were exported from Splunk as NDJSON and normalized into a consistent schema using `normalize.py`.

### Normalized Alert Schema

```json
{
  "alert_id": "uuid",
  "attack_type": "Kerberoasting | AS-REP Roasting | Lateral Movement",
  "timestamp": "ISO 8601 from Splunk _time",
  "event_code": "4769 | 4768 | 4624 | unknown",
  "source_host": "ComputerName",
  "account": "Account_Name",
  "source_ip": "Client_Address or IpAddress",
  "service_name": "Service_Name or null",
  "logon_type": "Logon_Type or null",
  "ticket_encryption_type": "0x17 (RC4) | 0x12 (AES-256) | null",
  "raw_message": "_raw Splunk event",
  "log_source": "Splunk/WinEventLog:Security"
}
```

**Key normalization issues resolved:**
- Splunk field names use underscores (`Ticket_Encryption_Type` not `TicketEncryptionType`)
- Lateral movement filter required explicit `Account_Name=jsmith` - machine accounts had no `IpAddress`
- Splunk exports NDJSON by default - normalizer detects and handles both NDJSON and JSON array formats

---

## Phase 3 - AI Triage Engine

### System Prompt (SOC Analyst Role)

```python
SYSTEM_PROMPT = """
You are a Tier 1 SOC analyst assistant. You analyze SIEM alerts and produce
structured triage reports. For every alert, respond ONLY with valid JSON:

{
  "severity": "Critical | High | Medium | Low",
  "verdict": "True Positive | Likely True Positive | Requires Investigation | Likely False Positive",
  "mitre_tactic": "TA00XX - Tactic Name",
  "mitre_technique": "T1XXX - Technique Name",
  "mitre_confidence": "High | Medium | Low",
  "false_positive_probability": integer 0-100,
  "escalate": true or false,
  "escalation_reason": "string or null",
  "evidence_summary": "2-3 sentence analyst summary",
  "recommended_next_steps": ["step 1", "step 2", "step 3"],
  "analyst_notes": "caveats, confidence gaps, missing data"
}

Rules:
- Base analysis strictly on alert fields provided
- Lower confidence when fields are null or missing — never invent data
- Never fabricate IOCs, IPs, or account names not in the alert
- Kerberoasting = T1558.003. AS-REP Roasting = T1558.004.
  Lateral Movement = T1550.002 or T1021
"""
```

### Triage Engine

```python
import anthropic
import json
import time
from dotenv import load_dotenv

load_dotenv()
client = anthropic.Anthropic()

def triage_alert(alert: dict) -> dict:
    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"Triage this SIEM alert:\n\n{json.dumps(alert, indent=2)}"
        }]
    )
    raw = message.content[0].text
    clean = raw.replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        return {"error": "Failed to parse AI response", "raw": raw}
```

### AI Triage Results - Summary

| Attack Type | AI Verdict | Count | Correct? |
|---|---|---|---|
| Kerberoasting (jsmith, RC4 0x17) | High / Likely True Positive | 2 | ✅ Yes |
| Kerberoasting (machine accounts, AES 0x12) | Low / Likely False Positive | 16 | ✅ Yes |
| AS-REP Roasting (jsmith, external IP) | High / Requires Investigation | 2 | ✅ Yes |
| AS-REP Roasting (machine accounts) | Low / Likely False Positive | 5 | ✅ Yes |
| Lateral Movement (jsmith, Logon Type 3) | High / Requires Investigation | 13 | ✅ Yes |

**The AI correctly differentiated:**
- RC4 (0x17) = Kerberoasting indicator vs AES (0x12) = normal traffic
- User account SPNs = attack targets vs machine account SPNs = normal domain behavior
- jsmith network logons from Kali IP = suspicious vs DC self-authentication = benign

---

## Phase 4 - Analyst Dashboard

A single-file HTML dashboard (`dashboard/dashboard.html`) served via Python HTTP server displays all 38 triage results.

```bash
# Serve dashboard
cd ~/soc-triage-ai
python3 -m http.server 8080
# Open: http://localhost:8080/dashboard/dashboard.html
```

**Dashboard features:**
- Alert queue (left panel) - all 38 alerts with severity badges and escalation indicators
- AI triage panel - severity, verdict, MITRE tactic/technique, confidence, false positive %, escalation reason, evidence summary, recommended next steps
- Manual analyst triage panel - dropdown fields for severity, verdict, escalation, and free-text notes
- AI vs Analyst comparison row - ✅ match / ❌ mismatch per field with comment input explaining reasoning

---

## Phase 5 - AI Failure Analysis

Three deliberately degraded test cases were fed to the triage engine to identify failure modes.

### Test Cases

| Alert ID | Description | Purpose |
|---|---|---|
| test-001 | All fields null/unknown | Test behavior with zero data |
| test-002 | Minimal data - "User logged on." raw message only | Test vague log handling |
| test-003 | Real SQL SPN with AES (0x12) encryption | Test encryption type knowledge |

### Failure Found - test-003 (Encryption Type Hallucination)

**Alert:** `jsmith` requesting TGS for `MSSQLSvc/sqlserver.lab.local:1433`, encryption type `0x12`

**AI Output:** Likely True Positive - High severity - High MITRE confidence

**AI Analyst Notes (verbatim):**
> *"RC4 encryption type (0x12) is a key indicator as modern environments typically use AES"*

**What went wrong:**  
The AI inverted the encryption type mapping. `0x12` is AES-256 - the strongest Kerberos encryption and a sign of completely normal traffic. `0x17` is RC4 - the actual Kerberoasting indicator. The AI stated this backwards **with High confidence**, which would cause a false escalation in a real SOC.

**Correct analyst verdict:** False Positive - named SQL SPN using AES-256 is normal domain behavior.

### Other Test Results

| Test | AI Verdict | Failure? | Notes |
|---|---|---|---|
| test-001 (empty) | Low / Requires Investigation | ✅ None | Correctly lowered confidence with no data |
| test-002 (vague) | High / Requires Investigation | ✅ None | Reasonable but unactionable — garbage in, garbage out |
| test-003 (AES SPN) | High / Likely True Positive | ❌ Hallucination | Wrong encryption mapping stated with High confidence |

### Key Finding

> AI confidence scores cannot be trusted on technical detail accuracy. The model performed well when data was clearly present or clearly absent. It failed when partial data existed and it filled gaps with incorrect technical assumptions stated confidently. Human analyst review is not optional - it is a requirement.

---

## Detection Logic - Analyst Reference

### Kerberoasting (T1558.003)

| Indicator | Malicious | Benign |
|---|---|---|
| Encryption type | 0x17 (RC4) | 0x12 / 0x11 (AES) |
| Requesting account | User account | Machine account ($) |
| Target SPN | User-named SPN | Machine account SPN |
| Source IP | External workstation | Localhost (::1) |

### AS-REP Roasting (T1558.004)

| Indicator | Malicious | Benign |
|---|---|---|
| Target account | User account, DONT_REQ_PREAUTH set | Machine account |
| Source IP | External IP | Localhost (::1) |
| Volume | Multiple accounts targeted | Single self-auth |

### Lateral Movement (T1021 / T1550.002)

| Indicator | Suspicious | Benign |
|---|---|---|
| Logon Type | 3 (Network) from unexpected source | 3 from known admin host |
| Account | Standard user on sensitive host | Admin on admin host |
| Timing | Off-hours, burst pattern | Business hours, single event |
| Source | Kali / attacker IP | Known internal workstation |

---

## Skills Demonstrated

- Active Directory attack simulation (Kerberoasting, AS-REP Roasting, lateral movement via Impacket and CrackMapExec)
- Splunk SPL query writing and alert export
- Alert normalization and schema design in Python
- Claude API integration with structured JSON output enforcement
- SOC analyst system prompt engineering
- MITRE ATT&CK technique mapping (T1558.003, T1558.004, T1021.002, T1550.002)
- AI triage auditing - identifying hallucinations and failure modes
- Custom SOC dashboard development (HTML/CSS/JavaScript)
- Detection gap analysis and analyst commentary

---

## Cost & Infrastructure

| Resource | Cost |
|---|---|
| Anthropic API (38 alerts + failure testing) | ~$0.58 |
| Splunk Enterprise (free trial) | $0 |
| VMware Workstation | existing license |
| Total project cost | < $1 |

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Anthropic Claude API Documentation](https://docs.anthropic.com)
- [Splunk SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Windows Security Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Impacket Suite](https://github.com/fortra/impacket)

---

**Author:** Durga Sai Sri Ramireddy | MS Cybersecurity, University of Houston  
[![LinkedIn](https://img.shields.io/badge/-LinkedIn-0072b1?style=flat&logo=linkedin&logoColor=white)](https://linkedin.com/in/durga-ramireddy)
[![GitHub](https://img.shields.io/badge/-GitHub-181717?style=flat&logo=github&logoColor=white)](https://github.com/DurgaRamireddy)
