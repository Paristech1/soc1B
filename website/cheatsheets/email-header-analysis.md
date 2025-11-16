# Email Header Analysis Cheat Sheet

## Key Header Fields

| Field | Purpose | What to Look For |
|-------|---------|------------------|
| **From** | Displayed sender address | May be spoofed - don't trust this alone! |
| **Received** | Shows mail server path | Read bottom-to-top to trace origin |
| **Return-Path** | Bounce-back address | Often reveals true sender |
| **X-Originating-IP** | Source IP address | Compare with claimed sender domain |
| **Received-SPF** | SPF authentication result | "fail" = red flag for spoofing |
| **DKIM-Signature** | Cryptographic signature | Validates email integrity |
| **DMARC** | Policy enforcement | Determines action on failed emails |
| **Message-ID** | Unique message identifier | Can reveal email client |
| **Reply-To** | Reply address | May differ from From (red flag) |

## Reading Received Headers

**Critical Rule:** Read `Received` headers from **bottom to top**

- **Bottom-most** = First server (origin)
- **Top-most** = Last server (your mail server)

### Example Analysis:
```
Received: from mail.example.com (last server - YOUR server)
Received: from mail.amazon-security.com [203.0.113.45] (intermediate)
Received: from attacker.malicious.net [198.51.100.50] (FIRST - TRUE ORIGIN)
```

## SPF (Sender Policy Framework)

| Result | Meaning | Action |
|--------|---------|--------|
| **pass** | ✅ IP is authorized | Email likely legitimate |
| **fail** | ❌ IP is NOT authorized | Likely spoofed - block |
| **neutral** | ⚠️ No policy found | Investigate further |
| **softfail** | ⚠️ Policy suggests failure | Treat as suspicious |
| **none** | No SPF record | Domain not protected |

### SPF Header Format:
```
Received-SPF: fail (google.com: domain of example.com does not designate 192.0.2.1 as permitted sender)
```

## DKIM (DomainKeys Identified Mail)

| Result | Meaning | Action |
|--------|---------|--------|
| **pass** | ✅ Signature valid | Email authenticated |
| **fail** | ❌ Signature invalid | Email may be tampered with |
| **none** | No DKIM signature | Domain doesn't use DKIM |

### DKIM Header Format:
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; 
    d=example.com; s=selector1; 
    h=from:to:subject:date; 
    bh=abc123def456; 
    b=xyz789
```

## DMARC (Domain-based Message Authentication)

| Result | Meaning | Action |
|--------|---------|--------|
| **pass** | ✅ Email passes policy | Likely legitimate |
| **fail** | ❌ Email fails policy | Likely spoofed |
| **quarantine** | Policy violation | Quarantine email |
| **reject** | Policy violation | Reject email |

### DMARC Header Format:
```
Authentication-Results: mail.example.com;
    dmarc=fail action=quarantine header.from=example.com
```

## Common Spoofing Indicators

1. ✅ **SPF failure** - IP not authorized
2. ✅ **DKIM failure** - Signature invalid
3. ✅ **DMARC failure** - Policy violation
4. ✅ **Suspicious originating IP** - Doesn't match domain
5. ✅ **Domain similarity** - Typosquatting (amazon-security.com vs amazon.com)
6. ✅ **Newly registered domain** - Less than 90 days old
7. ✅ **Return-Path mismatch** - Different from From field
8. ✅ **X-Originating-IP mismatch** - Doesn't match claimed domain

## Quick Analysis Workflow

1. **Extract raw header** from email client
2. **Read Received headers** bottom-to-top
3. **Check authentication** (SPF/DKIM/DMARC)
4. **Compare IPs** - Do they match claimed domain?
5. **Check domain age** - Is it newly registered?
6. **Look for typosquatting** - Similar but different domain
7. **Document IOCs** - IPs, domains, email addresses

## Linux Commands for Header Analysis

```bash
# Extract headers from .eml file
cat email.eml | grep -E "^Received:|^From:|^Return-Path:|^X-Originating-IP:"

# Parse Received headers in reverse order
tac email.eml | grep "^Received:" | head -1

# Check SPF result
grep -i "received-spf" email.eml

# Extract all IPs from headers
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" email.eml | sort -u
```

## Online Tools

- **MXToolbox Email Header Analyzer**: https://mxtoolbox.com/EmailHeaders.aspx
- **Google Admin Toolbox**: https://toolbox.googleapps.com/apps/messageheader/
- **MessageHeader.org**: https://www.messageheader.org/

## Red Flags Summary

| Red Flag | Severity | Action |
|----------|----------|--------|
| SPF fail | 🔴 High | Block email, investigate |
| DKIM fail | 🟡 Medium | Investigate further |
| DMARC fail | 🔴 High | Quarantine or block |
| IP mismatch | 🔴 High | Block IP, investigate |
| New domain | 🟡 Medium | Investigate, may be legitimate |
| Typosquatting | 🔴 High | Block domain |

