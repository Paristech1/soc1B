# Detection Rule Development Template

**Purpose:** Standardized documentation for creating and deploying new detection logic (Suricata, YARA, Sigma).

**Rule ID:** [RULE-XXXX]  
**Date Created:** [YYYY-MM-DD]  
**Created By:** [Analyst Name]  
**Status:** [DRAFT / TESTING / STAGING / PRODUCTION]

---

## Rule Information

| Field | Description | Example |
|-------|-------------|---------|
| **Rule Name** | Concise, descriptive name for the detection | `WIN_Suspicious_PowerShell_Execution` |
| **Rule ID (SID)** | Unique identifier for the rule | `1000005` |
| **Rule Type** | Suricata / YARA / Sigma | `Sigma` |
| **Threat Category** | MITRE ATT&CK Tactic/Technique | `T1059.001 (PowerShell)` |
| **Log Source** | Where the rule is applied | `Windows Event Log (Security)` |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW | `HIGH` |
| **Confidence** | CONFIRMED / HIGH / MEDIUM / LOW | `HIGH` |

---

## Threat Context

### Attack Description

[Description of the attack or behavior this rule is designed to detect]

**Example:**
> This rule detects suspicious PowerShell execution patterns commonly used by attackers to evade detection. It identifies PowerShell commands that use encoded commands or download and execute scripts from external sources, which are common techniques in malware delivery and lateral movement.

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Description |
|--------|--------------|----------------|-------------|
| | | | |

**Example:**
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Detects PowerShell execution with encoded commands |
| Defense Evasion | T1027 | Obfuscated Files or Information | Detects obfuscated PowerShell commands |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Detects PowerShell downloading scripts from external sources |

### Known Attack Examples

- [Example 1]
- [Example 2]
- [Example 3]

---

## Detection Logic

### Detection Logic (Plain English)

[The core condition(s) of the rule described in plain English]

**Example:**
> Detects `EventID 4688` (process creation) where `ProcessName` is `powershell.exe` and `CommandLine` contains indicators of suspicious activity such as:
> - `IEX` (Invoke-Expression)
> - `EncodedCommand` parameter
> - Base64 encoded strings longer than 100 characters
> - `DownloadString` or `DownloadFile` methods
> - Connections to external IPs

### Detection Conditions

| Condition | Operator | Value | Description |
|-----------|----------|-------|-------------|
| | | | |

---

## Rule Code

### Suricata Rule

```suricata
[Paste Suricata rule here]
```

**Example:**
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Potential Malware C2 Communication";
    flow:to_server,established;
    content:"GET"; http_method;
    content:"malware-c2.net"; http_host;
    sid:1000001;
    rev:1;
    classtype:trojan-activity;
    priority:1;
)
```

### YARA Rule

```yara
[Paste YARA rule here]
```

**Example:**
```yara
rule CryptoLocker_Variant {
    meta:
        description = "Detects CryptoLocker-like ransomware"
        author = "SOC Analyst"
        date = "2024-01-15"
        severity = "high"
    strings:
        $a = "C:\\Windows\\System32\\cmd.exe" ascii
        $b = "vssadmin.exe delete shadows" ascii
        $c = {4D 5A 90 00} // MZ header
        $d = /encrypt.*files/ nocase
    condition:
        $c at 0 and (2 of ($a, $b, $d))
}
```

### Sigma Rule

```yaml
[Paste Sigma rule YAML here]
```

**Example:**
```yaml
title: Suspicious PowerShell Execution
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects suspicious PowerShell execution patterns
author: SOC Analyst
date: 2024/01/15
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        ProcessName: 'powershell.exe'
        CommandLine|contains:
            - 'IEX'
            - 'EncodedCommand'
            - 'DownloadString'
    condition: selection
falsepositives:
    - Legitimate administrative scripts
level: high
```

### Converted SIEM Queries

**Splunk Query:**
```splunk
[Paste Splunk query here]
```

**Elasticsearch Query:**
```json
[Paste Elasticsearch query here]
```

**Microsoft Sentinel Query:**
```kql
[Paste KQL query here]
```

---

## Test Cases

### Positive Test Cases (Should Trigger)

| Test Case ID | Description | Expected Result | Status |
|--------------|-------------|-----------------|--------|
| | | | |

**Example:**
| TC-001 | Execute `powershell.exe -e <base64_string>` | Rule triggers | ☐ PASS / ☐ FAIL |
| TC-002 | PowerShell downloads script from external URL | Rule triggers | ☐ PASS / ☐ FAIL |

### Negative Test Cases (Should Not Trigger)

| Test Case ID | Description | Expected Result | Status |
|--------------|-------------|-----------------|--------|
| | | | |

**Example:**
| TC-101 | Normal PowerShell execution with `-Command` parameter | Rule does not trigger | ☐ PASS / ☐ FAIL |
| TC-102 | Legitimate administrative PowerShell script | Rule does not trigger | ☐ PASS / ☐ FAIL |

### Test Results

**Test Date:** [YYYY-MM-DD]  
**Tested By:** [Tester Name]  
**Test Environment:** [Environment Name]

| Test Case | Result | Notes |
|-----------|--------|-------|
| | | |

---

## False Positive Analysis

### Potential False Positives

| Scenario | Likelihood | Mitigation |
|----------|------------|------------|
| | | |

**Example:**
| Legitimate administrative scripts using encoded commands | MEDIUM | Add whitelist for known administrative accounts |
| Development/testing environments | HIGH | Exclude test/dev environments from rule scope |

### Tuning Recommendations

1. [ ]
2. [ ]
3. [ ]

---

## Performance Impact

| Metric | Value | Notes |
|--------|-------|-------|
| **Query Execution Time** | | |
| **CPU Impact** | | |
| **Memory Impact** | | |
| **Network Impact** | | |
| **Expected Alert Volume** | | |

---

## Deployment Plan

### Deployment Stages

| Stage | Environment | Date | Status |
|-------|-------------|------|--------|
| **Testing** | Test Lab | | ☐ |
| **Staging** | Staging SIEM | | ☐ |
| **Production** | Production SIEM | | ☐ |

### Deployment Steps

1. [ ]
2. [ ]
3. [ ]

### Rollback Plan

[Description of how to rollback the rule if issues arise]

---

## Monitoring & Metrics

### Key Metrics to Monitor

- **Alert Volume:** [Expected alerts per day/week]
- **False Positive Rate:** [Target: < 5%]
- **True Positive Rate:** [Target: > 90%]
- **Performance Impact:** [CPU/Memory usage]

### Monitoring Queries

[Queries to monitor rule performance and effectiveness]

---

## Related Rules

| Rule ID | Rule Name | Relationship |
|---------|-----------|-------------|
| | | Complementary / Related / Supersedes |

---

## References

- [Link to threat intelligence report]
- [Link to MITRE ATT&CK technique]
- [Link to related research/analysis]

---

## Change Log

| Date | Version | Author | Changes |
|------|---------|--------|---------|
| | | | Initial creation |

---

**Status:** [DRAFT / TESTING / STAGING / PRODUCTION]  
**Last Updated:** [YYYY-MM-DD]  
**Next Review Date:** [YYYY-MM-DD]

