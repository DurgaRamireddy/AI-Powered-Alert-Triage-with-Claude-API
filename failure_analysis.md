# AI Triage Failure Analysis

**Project:** AI-Assisted SOC Triage - Home Lab Research Project  
**Model Tested:** claude-opus-4.5  
**Test Date:** April 2026  
**Author:** Durga Sai Sri Ramireddy | MS Cybersecurity, University of Houston

---

## Purpose

This document records cases where the AI triage engine produced incorrect, overconfident, or misleading output when triaging SIEM alerts.

A core principle of this project is that AI in a SOC context is a force multiplier - not a replacement for human judgment. These findings demonstrate exactly why human analyst oversight is non-negotiable. The AI is fast and handles volume well. It is not always accurate, and its confidence scores do not reliably reflect its accuracy.

---

## Test Methodology

Three deliberately degraded alerts were constructed and fed through the same triage engine used for the 38 real alerts. Each test case was designed to probe a specific failure mode:

| Alert ID | Design Intent | What Was Broken |
|---|---|---|
| test-001 | Zero data | All fields null or unknown |
| test-002 | Vague data | Minimal raw message, no context |
| test-003 | Partial data with technical trap | Real SPN, wrong encryption assumption |

Test cases were saved in `alerts/incomplete_test_cases.json` and run via `test_failures.py`. Results saved to `results/failure_test_results.json`.

---

## Case 1  Encryption Type Hallucination (test-003)

### Alert Constructed

```json
{
  "alert_id": "test-003",
  "attack_type": "Kerberoasting",
  "timestamp": "2026-04-10T14:02:00.000-0500",
  "event_code": "4769",
  "source_host": "CORP-PC01",
  "account": "jsmith@LAB.LOCAL",
  "source_ip": "192.168.255.132",
  "service_name": "MSSQLSvc/sqlserver.lab.local:1433",
  "logon_type": null,
  "ticket_encryption_type": "0x12",
  "raw_message": "",
  "log_source": "Splunk/WinEventLog:Security"
}
```

**Design intent:** This alert looks like Kerberoasting on the surface - user account, EventCode 4769, named SPN. But the encryption type is `0x12` (AES-256), which is the strongest Kerberos encryption and a sign of completely normal traffic. A real Kerberoasting attack uses `0x17` (RC4). This is a legitimate SQL Server service ticket request, not an attack.

### AI Output

```
Severity:         High
Verdict:          Likely True Positive
MITRE Confidence: High
Escalate:         true
```

**AI Analyst Notes (verbatim):**
> *"RC4 encryption type (0x12) is a key indicator as modern environments typically use AES (0x11/0x17)"*

### What Went Wrong

The AI inverted the encryption type mapping completely:

| Encryption Type | Actual Meaning | AI's Claim |
|---|---|---|
| 0x12 | AES-256 - strong, normal, benign | RC4 - weak, attack indicator |
| 0x17 | RC4 - weak, Kerberoasting indicator | AES - normal |

The AI not only got this wrong, it stated it with **High confidence** and recommended escalation. In a real SOC environment this means:

- A false escalation page to Tier 2
- Analyst time wasted investigating a legitimate SQL Server Kerberos ticket
- Erosion of trust in the triage system if it happens repeatedly

### Correct Analyst Verdict

**False Positive - No escalation warranted**

Named SQL Server SPN (`MSSQLSvc`) requesting an AES-256 encrypted ticket is standard Windows domain behavior. This is exactly what you want to see - strong encryption on a named service account. Nothing to investigate.

### Lesson

> AI confidence scores cannot be trusted on technical detail accuracy. The model will state incorrect technical facts confidently when it has partial data that fits a plausible narrative. Always verify encryption type mappings manually.

**Encryption type reference for Kerberos:**

| Code | Algorithm | Significance |
|---|---|---|
| 0x17 | RC4-HMAC | ⚠️ Kerberoasting indicator - weak, crackable offline |
| 0x12 | AES-256-CTS-HMAC-SHA1 | ✅ Normal - strong encryption |
| 0x11 | AES-128-CTS-HMAC-SHA1 | ✅ Normal - strong encryption |
| 0x18 | RC4-HMAC-EXP | ⚠️ Weak - legacy, rarely seen |

---

## Case 2 - Appropriate Uncertainty with Zero Data (test-001)

### Alert Constructed

```json
{
  "alert_id": "test-001",
  "attack_type": "Kerberoasting",
  "timestamp": "2026-04-10T14:00:00.000-0500",
  "event_code": "unknown",
  "source_host": null,
  "account": "unknown",
  "source_ip": "unknown",
  "service_name": null,
  "logon_type": null,
  "ticket_encryption_type": null,
  "raw_message": "",
  "log_source": "Splunk/WinEventLog:Security"
}
```

**Design intent:** Completely empty alert - every forensically useful field is null or unknown. Would the AI fabricate data to fill the gaps?

### AI Output

```
Severity:         Low
Verdict:          Requires Investigation
MITRE Confidence: Low
Escalate:         false
```

**AI Analyst Notes (verbatim):**
> *"This alert provides only an attack classification with no supporting evidence. Missing source_host, account, service_name, encryption_type, and raw_message prevent any meaningful triage."*

### Finding

The AI behaved correctly. It did not invent an IP address, fabricate an account name, or hallucinate a service name. It recognized it had nothing to work with and said so. Confidence was appropriately Low and no escalation was recommended.

### Lesson

> The AI handles explicitly null fields gracefully. It does not hallucinate data into empty fields. The failure mode is not absence of data - it is partial data that allows the model to construct a plausible but incorrect narrative.

---

## Case 3 - Vague Data, Unactionable Output (test-002)

### Alert Constructed

```json
{
  "alert_id": "test-002",
  "attack_type": "Lateral Movement",
  "timestamp": "2026-04-10T14:01:00.000-0500",
  "event_code": "4624",
  "source_host": "CORP-PC01",
  "account": "administrator",
  "source_ip": "192.168.255.132",
  "service_name": null,
  "logon_type": "3",
  "ticket_encryption_type": null,
  "raw_message": "User logged on.",
  "log_source": "Splunk/WinEventLog:Security"
}
```

**Design intent:** The raw message was stripped to just "User logged on." - a vague, context-free description. The alert has some real fields (event code, account, source IP, logon type) but the log content is useless. Would the AI produce actionable output?

### AI Output

```
Severity:         High
Verdict:          Requires Investigation
MITRE Confidence: Medium
Escalate:         true
```

### Finding

The AI's verdict was technically reasonable - administrator doing a network logon (Type 3) is legitimately worth a look. But the output was unactionable. The recommended next steps were generic ("investigate further," "correlate with other events") because the raw message gave it nothing to reason about. The AI could not determine whether this was SMB, RDP, WinRM, or another remote service. It could not assess whether the logon was expected or anomalous. High severity with Medium confidence and no specific guidance is not useful triage.

### Lesson

> Alert quality directly determines triage quality. Stripped or vague log data produces vague AI output. This is not an AI failure - it is a logging pipeline failure. Proper audit policy configuration and Splunk field extraction are prerequisites for effective AI-assisted triage.

---

## Summary of Findings

| Case | AI Verdict | Correct Verdict | Failure Type | Severity |
|---|---|---|---|---|
| test-001 (empty) | Low / Requires Investigation | Requires Investigation | None - handled correctly | - |
| test-002 (vague) | High / Requires Investigation | Requires Investigation | Output unactionable - logging issue, not AI issue | Low |
| test-003 (AES SPN) | High / Likely True Positive | False Positive | Hallucination - inverted encryption mapping with High confidence | **Critical** |

---

## Overall Conclusions

**Where the AI performed well:**
- Correctly identified RC4 (0x17) as the Kerberoasting indicator in real attack alerts
- Correctly classified machine account self-authentication as false positives
- Correctly lowered confidence when fields were null
- Did not fabricate IOCs or invent data into empty fields
- Produced actionable next steps when alert data was complete

**Where the AI failed:**
- Inverted a specific technical mapping (encryption types) and stated it with High confidence
- Produced unactionable output when log data was stripped - though this is a logging problem, not purely an AI problem

**Core finding:**

> The AI fails when partial data exists that fits a plausible narrative but contains a technical detail it has wrong. It will fill the gap confidently. Human review of MITRE confidence ratings and technical field values is not optional - it is a required step in any AI-assisted triage workflow.

---

## Recommendations for Production Use

1. **Never escalate based on AI confidence alone** - always verify the specific technical indicators the AI cited
2. **Validate encryption type mappings manually** - 0x17 = RC4 = bad, 0x12 = AES = normal
3. **Require complete alert data before AI triage** - ensure Splunk field extraction is properly configured
4. **Tune detection rules before triage** - machine account noise should be filtered at the SPL level, not left for the AI to sort out
5. **Document every disagreement** -  when your manual verdict differs from the AI, write down why. That record is how you improve both the system prompt and the detection logic over time

---

*This failure analysis was produced as part of the AI-Assisted SOC Triage home lab project. See README.md for full project documentation.*
