# OSINT Tools Quick Reference

## VirusTotal

**URL:** https://www.virustotal.com/

### What It Does
- Scans files, URLs, domains, and IPs against 70+ antivirus engines
- Provides threat intelligence and reputation data

### Key Information to Extract
- **Detection Ratio**: Number of engines that flagged it
- **First Seen**: When the IOC was first observed
- **Last Seen**: Most recent observation
- **Community Comments**: Analyst notes and context

### API Usage
```bash
# Check IP address
curl -X GET "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=YOUR_API_KEY&ip=198.51.100.50"

# Check domain
curl -X GET "https://www.virustotal.com/vtapi/v2/domain/report?apikey=YOUR_API_KEY&domain=example.com"

# Check file hash
curl -X GET "https://www.virustotal.com/vtapi/v2/file/report?apikey=YOUR_API_KEY&resource=abc123def456"
```

### Interpreting Results
- **0/70 detections**: Clean (but verify with other tools)
- **1-5/70 detections**: Suspicious, investigate further
- **10+/70 detections**: Malicious, block immediately

---

## AbuseIPDB

**URL:** https://www.abuseipdb.com/

### What It Does
- IP reputation database with abuse reports
- Provides confidence scores and geographic data

### Key Information to Extract
- **Abuse Confidence**: 0-100 score (higher = more malicious)
- **Usage Type**: ISP, hosting, datacenter, etc.
- **ISP**: Internet Service Provider
- **Country**: Geographic location
- **Reports**: Number of abuse reports

### API Usage
```bash
# Check IP address
curl -X GET "https://api.abuseipdb.com/api/v2/check?ipAddress=198.51.100.50" \
  -H "Key: YOUR_API_KEY" \
  -H "Accept: application/json"
```

### Interpreting Results
- **0-25 confidence**: Low risk, likely legitimate
- **26-75 confidence**: Medium risk, investigate
- **76-100 confidence**: High risk, block immediately

---

## Whois

**URL:** https://whois.net/ or use command-line

### What It Does
- Domain registration information
- IP address ownership and allocation

### Key Information to Extract
- **Registrar**: Domain registrar company
- **Creation Date**: When domain was registered
- **Expiration Date**: When domain expires
- **Registrant**: Domain owner (may be privacy-protected)
- **Name Servers**: DNS servers for the domain

### Command-Line Usage
```bash
# Check domain
whois example.com

# Check IP address
whois 198.51.100.50

# Extract creation date
whois example.com | grep -i "creation date"

# Check if domain is newly registered (< 90 days)
whois example.com | grep -i "creation date"
```

### Red Flags
- **Newly registered** (< 90 days): Suspicious
- **Privacy protection**: May hide malicious actor
- **Free email registrant**: Often used by attackers
- **Recent expiration/renewal**: May indicate domain hijacking

---

## Shodan

**URL:** https://www.shodan.io/

### What It Does
- Internet-connected device search engine
- Shows open ports, services, and vulnerabilities

### Key Information to Extract
- **Open Ports**: Services exposed to internet
- **Banners**: Service version information
- **Vulnerabilities**: Known CVEs
- **Hosting Provider**: Datacenter or cloud provider
- **Geographic Location**: Country and city

### Search Queries
```
# Find all devices with specific IP
ip:198.51.100.50

# Find devices with specific port open
port:22 country:US

# Find devices with specific service
product:Apache country:CN

# Find vulnerable services
vuln:CVE-2021-44228
```

### API Usage
```bash
# Search for IP
curl -X GET "https://api.shodan.io/shodan/host/198.51.100.50?key=YOUR_API_KEY"
```

### Interpreting Results
- **Many open ports**: May indicate compromised system
- **Default credentials**: High risk
- **Known vulnerabilities**: Immediate threat
- **Suspicious services**: Unusual ports or services

---

## Additional OSINT Tools

### PassiveTotal (RiskIQ)
- Domain and IP intelligence
- Historical DNS records
- SSL certificate information

### URLVoid
- URL reputation checking
- Blacklist status across multiple engines

### Hybrid Analysis
- Malware sandbox analysis
- Behavioral analysis reports

### Censys
- Internet-wide scanning data
- Certificate transparency logs
- Similar to Shodan

---

## OSINT Workflow

1. **Start with VirusTotal** - Quick reputation check
2. **Check AbuseIPDB** - IP reputation and abuse reports
3. **Query Whois** - Domain registration details
4. **Search Shodan** - Exposed services and vulnerabilities
5. **Cross-reference** - Compare findings across tools
6. **Document IOCs** - Record all findings

## Quick Reference Table

| Tool | Best For | Key Metric |
|------|----------|------------|
| VirusTotal | Files, URLs, IPs, Domains | Detection ratio |
| AbuseIPDB | IP reputation | Abuse confidence (0-100) |
| Whois | Domain registration | Creation date |
| Shodan | Exposed services | Open ports, vulnerabilities |

## Common Red Flags

- ✅ **High detection ratio** (VirusTotal): 10+ engines flagging
- ✅ **High abuse confidence** (AbuseIPDB): 75+ confidence score
- ✅ **Newly registered domain** (Whois): < 90 days old
- ✅ **Many open ports** (Shodan): Unusual service exposure
- ✅ **Known vulnerabilities** (Shodan): CVE matches
- ✅ **Suspicious hosting** (Shodan): Bulletproof hosting providers

