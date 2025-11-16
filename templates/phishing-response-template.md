# Phishing Response Template

**Purpose:** A quick-reference checklist and documentation for a Tier 1 analyst handling a reported phishing email.

**INCIDENT ID:** [INCIDENT-YYYY-XXXX]  
**Date:** [YYYY-MM-DD]  
**Analyst:** [Your Name]  
**Reported By:** [User Name/Email]

---

## Phishing Response Checklist

| Step | Action | Status (Y/N/NA) | Notes/IOCs |
|------|--------|-----------------|------------|
| **1. Triage & Validation** | | | |
| | Isolate the email (move to quarantine/sandbox) | ☐ | |
| | Extract the raw email header | ☐ | |
| | Check SPF/DKIM/DMARC results in the header | ☐ | SPF: [ ] / DKIM: [ ] / DMARC: [ ] |
| | Check the `X-Originating-IP` against internal ranges | ☐ | IP: [ ] |
| | Verify sender domain against known legitimate domains | ☐ | Domain: [ ] |
| **2. Threat Enrichment (OSINT)** | | | |
| | Check all domains/IPs on VirusTotal | ☐ | Detection Ratio: [ ] |
| | Check all domains/IPs on AbuseIPDB/Whois | ☐ | Abuse Score: [ ] |
| | Is the domain newly registered (less than 90 days)? | ☐ | Registration Date: [ ] |
| | Check Shodan for exposed services on attacker IP | ☐ | Open Ports: [ ] |
| | Document all findings in threat intelligence report | ☐ | |
| **3. User Interaction Check** | | | |
| | Did the user click the link? | ☐ | |
| | Did the user open the attachment? | ☐ | |
| | If yes, isolate the user's host immediately | ☐ | Host: [ ] |
| | Reset the user's password and enforce MFA | ☐ | |
| | Initiate host-based forensics on compromised machine | ☐ | |
| **4. Containment & Eradication** | | | |
| | Block malicious domains/IPs at the firewall/proxy | ☐ | |
| | Remove the email from all other user inboxes | ☐ | |
| | Check for other users who received the same email | ☐ | Count: [ ] |
| | Initiate host-based forensics on the compromised machine | ☐ | |
| | Check network logs for C2 connections | ☐ | |
| **5. Documentation** | | | |
| | Create a formal Incident Ticket (using Template 1) | ☐ | Ticket #: [ ] |
| | Document all IOCs in threat intelligence database | ☐ | |
| | Notify the Security Awareness team for user re-training | ☐ | |
| | Update threat intelligence feeds with new IOCs | ☐ | |

---

## Email Header Analysis

### Raw Email Header

```
[Paste raw email header here]
```

### Key Findings

| Field | Value | Analysis |
|-------|-------|----------|
| **From** | | |
| **Return-Path** | | |
| **X-Originating-IP** | | |
| **Received (First)** | | |
| **Received (Last)** | | |
| **SPF Result** | | |
| **DKIM Result** | | |
| **DMARC Result** | | |

### Spoofing Indicators

- [ ] SPF failure
- [ ] DKIM failure
- [ ] DMARC failure
- [ ] Suspicious originating IP
- [ ] Domain similarity (typosquatting)
- [ ] Newly registered domain
- [ ] Other: [ ]

---

## OSINT Threat Enrichment Results

### VirusTotal Results

| IOC | Type | Detection Ratio | First Seen | Last Seen |
|-----|------|----------------|------------|-----------|
| | | | | |

### AbuseIPDB Results

| IP Address | Abuse Confidence | Reports | Country | ISP |
|------------|------------------|---------|---------|-----|
| | | | | |

### Whois Results

| Domain | Registrar | Creation Date | Registrant | Name Servers |
|--------|-----------|--------------|------------|--------------|
| | | | | |

### Shodan Results

| IP Address | Open Ports | Services | Hosting Provider |
|------------|-----------|----------|------------------|
| | | | |

---

## User Impact Assessment

| User | Email Address | Host | Interaction | Status |
|------|--------------|------|------------|--------|
| | | | Clicked Link / Opened Attachment / No Action | Isolated / Monitoring / Cleared |

---

## Containment Actions Taken

| Action | Timestamp | Performed By | Details |
|--------|-----------|--------------|---------|
| | | | |

---

## Recommended Next Steps

1. [ ]
2. [ ]
3. [ ]

---

## Notes

[Additional notes, observations, or findings]

---

**Status:** [OPEN / IN PROGRESS / RESOLVED]  
**Assigned To:** [Analyst Name]  
**Next Review:** [Date/Time]

