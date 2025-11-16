# Incident Report Template (NIST 800-61 Aligned)

**INCIDENT ID:** [INCIDENT-YYYY-XXXX]  
**Date Created:** [YYYY-MM-DD]  
**Created By:** [Analyst Name]  
**Status:** [OPEN / IN PROGRESS / RESOLVED / CLOSED]  
**Severity:** [CRITICAL / HIGH / MEDIUM / LOW]

---

## 1. Executive Summary

**(1-2 Paragraphs)**  
Incident title, date/time discovered, current status, business impact, and key findings. **MUST** be non-technical and suitable for executive management.

**Example:**
> On [DATE] at [TIME], a phishing email was reported by a user in the Finance department. Investigation revealed that the email contained a malicious link that, when clicked, established a command-and-control connection to an external server. The incident was contained within 2 hours, and no sensitive data was confirmed to have been exfiltrated. The affected user's account was disabled, and the host was isolated for forensic analysis.

---

## 2. Incident Details

| Field | Information |
|-------|-------------|
| **Incident Type** | (e.g., Phishing, Unauthorized Access, Malware, DDoS, Data Exfiltration) |
| **Severity** | (CRITICAL / HIGH / MEDIUM / LOW) |
| **Discovery Method** | (e.g., SIEM Alert, User Report, Threat Intelligence) |
| **Discovery Time** | [YYYY-MM-DD HH:MM:SS UTC] |
| **Affected Assets** | Hostnames, IPs, User Accounts, Systems |
| **Business Impact** | (e.g., Service Disruption, Data Breach, Financial Loss) |

---

## 3. Timeline of Events

Chronological list of key events with timestamps (UTC preferred). **MUST** include: Initial Access, Detection, Containment, Eradication, and Recovery.

| Timestamp (UTC) | Event | Description | Source |
|-----------------|-------|-------------|--------|
| 2024-01-15 10:30:45 | Initial Access | Phishing email received by user | Email Server Logs |
| 2024-01-15 10:31:00 | User Interaction | User clicked malicious link | User Report |
| 2024-01-15 10:31:05 | Malware Download | Malware downloaded from external server | PCAP Analysis |
| 2024-01-15 10:32:00 | C2 Establishment | Command-and-control connection established | Network Logs |
| 2024-01-15 10:35:00 | Detection | SIEM alert fired on suspicious outbound connection | SIEM |
| 2024-01-15 10:40:00 | Containment | Host isolated from network, user account disabled | SOC Actions |
| 2024-01-15 11:00:00 | Eradication | Malware removed, system patched | IT Operations |
| 2024-01-15 14:00:00 | Recovery | System restored from clean backup | IT Operations |

---

## 4. Investigation Findings

### Technical Analysis

#### Indicators of Compromise (IOCs)

| Type | Value | Source | Status |
|------|-------|--------|--------|
| **IP Address** | 198.51.100.50 | PCAP Analysis | Blocked |
| **Domain** | amazon-security.com | Email Header | Blocked |
| **File Hash (MD5)** | d41d8cd98f00b204e9800998ecf8427e | Malware Analysis | Quarantined |
| **File Hash (SHA-256)** | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | Malware Analysis | Quarantined |
| **URL** | http://203.0.113.45/verify.php | Email Analysis | Blocked |

#### Log Analysis

**Key Log Entries:**
- [Include relevant log excerpts with timestamps]
- [Document suspicious activities found in logs]

#### Malware Analysis Summary (if applicable)

- **Malware Family:** [e.g., Emotet, TrickBot]
- **Behavior:** [e.g., Establishes C2, Exfiltrates data]
- **Persistence Mechanisms:** [e.g., Registry Run Key, Scheduled Task]

### Scope

- **Systems Affected:** [List of affected systems]
- **Users Affected:** [List of affected user accounts]
- **Data Accessed:** [Description of data that may have been accessed]
- **Network Segments Affected:** [List of affected network segments]

---

## 5. Containment, Eradication, & Recovery

### Containment Actions

| Action | Timestamp | Performed By | Details |
|--------|-----------|--------------|---------|
| Host Isolation | 2024-01-15 10:40:00 | SOC Analyst | Disconnected host 192.168.1.100 from network |
| Account Suspension | 2024-01-15 10:40:15 | SOC Analyst | Disabled user account: jdoe@example.com |
| Firewall Block | 2024-01-15 10:40:30 | Network Team | Blocked IP 198.51.100.50 at firewall |
| DNS Block | 2024-01-15 10:41:00 | DNS Team | Blocked domain amazon-security.com |

### Eradication Steps

| Action | Timestamp | Performed By | Details |
|--------|-----------|--------------|---------|
| Malware Removal | 2024-01-15 11:00:00 | IT Operations | Removed malware files from system |
| Credential Reset | 2024-01-15 11:15:00 | IT Operations | Reset password for jdoe@example.com |
| Vulnerability Patching | 2024-01-15 11:30:00 | IT Operations | Applied security patches |
| Registry Cleanup | 2024-01-15 11:45:00 | IT Operations | Removed persistence mechanisms |

### Recovery Steps

| Action | Timestamp | Performed By | Details |
|--------|-----------|--------------|---------|
| System Restoration | 2024-01-15 14:00:00 | IT Operations | Restored system from clean backup |
| Monitoring | 2024-01-15 14:00:00 | SOC Team | Enhanced monitoring for 48 hours |
| User Re-enablement | 2024-01-15 15:00:00 | IT Operations | Re-enabled user account with new credentials |

---

## 6. Root Cause Analysis (RCA)

**The underlying vulnerability or failure that allowed the incident:**

- **Primary Cause:** [e.g., User clicked malicious link in phishing email]
- **Contributing Factors:** [e.g., Lack of email security awareness, Missing email security controls]
- **Vulnerabilities Exploited:** [e.g., Unpatched software, Weak password policy]
- **Security Control Gaps:** [e.g., No email filtering, No endpoint detection]

---

## 7. Lessons Learned & Recommendations

### Short-Term Recommendations (Immediate Actions)

1. [Immediate configuration change or action]
2. [Additional monitoring or detection]
3. [User awareness training]

### Long-Term Recommendations

1. **Policy Changes:** [e.g., Implement mandatory MFA for all users]
2. **Technical Controls:** [e.g., Deploy advanced email security solution]
3. **Training Needs:** [e.g., Phishing awareness training for all employees]
4. **Tool Acquisition:** [e.g., Enhanced endpoint detection and response (EDR) solution]

---

## 8. Appendices

### Appendix A: Raw IOC List

[Complete list of all IOCs in structured format]

### Appendix B: Screenshots

[Links to or embedded screenshots of key evidence]

### Appendix C: Log Excerpts

[Raw log excerpts for reference]

### Appendix D: Memory Analysis Report

[Link to full memory forensics report if applicable]

---

**Report Status:** [DRAFT / FINAL]  
**Next Review Date:** [YYYY-MM-DD]  
**Approved By:** [Manager Name]  
**Date Approved:** [YYYY-MM-DD]

