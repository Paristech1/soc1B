# SOC Analyst I — Hands-On Labs, Portfolio Projects, and Capstone Challenges

This guide provides the practical, step-by-step exercises, portfolio projects, and capstone challenges from the "SOC Analyst I — From Cradle to Grave" course. These labs are designed to be completed using open-source tools and synthetic data to build a strong, job-ready portfolio.

---

## Module 1: Phishing Attack — Labs and Projects

### Lab 1.1: Email Header Analysis and Spoofing Detection

**Objective:** Extract and analyze email headers to identify spoofing and determine the true origin of an email.

**Tools Required:** Text editor, online header analyzer (e.g., MXToolbox Email Header Analyzer), or command-line tools.

**Sample Email Header (Spoofed):**

```
Received: from mail.amazon-security.com (mail.amazon-security.com [203.0.113.45])
    by mail.example.com with SMTP id h12sm2345678pdb.0.2024.01.15.10.30.45
    for <user@example.com>;
    Mon, 15 Jan 2024 10:30:45 -0800 (PST)
Received: from attacker.malicious.net [198.51.100.50] by mail.amazon-security.com with SMTP id a1b2c3d4e5f6g7h8
    for <user@example.com>;
    Mon, 15 Jan 2024 10:25:00 -0800
Return-Path: <noreply@amazon-security.com>
Received-SPF: fail (google.com: domain of amazon-security.com does not designate 198.51.100.50 as permitted sender)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=amazon-security.com; ...
From: Amazon Security <noreply@amazon-security.com>
To: user@example.com
Subject: Urgent: Verify Your Account
Date: Mon, 15 Jan 2024 10:30:45 -0800
Message-ID: <abc123@amazon-security.com>
X-Originating-IP: [198.51.100.50]
```

**Lab Steps:**

1.  Copy the sample header into a text editor. Read the `Received` lines from bottom to top. Identify the first server that received the email: `attacker.malicious.net [198.51.100.50]`.
2.  Check the `X-Originating-IP`. It matches the attacker's IP: `198.51.100.50`. This is a red flag.
3.  Examine the `Received-SPF` line. It shows `fail`, meaning the email did not pass SPF validation.
4.  Check the `From` address: `noreply@amazon-security.com`. Note that this looks legitimate, but the SPF failure and originating IP contradict it.
5.  **Conclusion:** This email is spoofed. The attacker registered a domain similar to Amazon's and sent the email from their own server. The SPF failure confirms this.

**Deliverable:** A one-page analysis document identifying the spoofing indicators and explaining why this email is malicious.

---

### Lab 1.2: OSINT Threat Enrichment

**Objective:** Enrich the IOCs from the spoofed email with threat intelligence using open-source tools.

**IOCs to Investigate:**

*   Domain: `amazon-security.com`
*   IP Address: `198.51.100.50`
*   Email: `noreply@amazon-security.com`

**Lab Steps:**

1.  **VirusTotal Domain Check:** Visit `virustotal.com` and search for `amazon-security.com`. Document the creation date, registrar, and any security vendor detections.
2.  **Whois Lookup:** Use a Whois tool (e.g., `whois.com` or command-line `whois`) to check the domain registration. Look for the registrant name, creation date, and registrar.
3.  **Shodan IP Search:** Use `shodan.io` to search for the IP address `198.51.100.50`. Document any open ports, services, or hosting provider information.
4.  **AbuseIPDB Check:** Visit `abuseipdb.com` and search for `198.51.100.50`. Look for historical abuse reports and the confidence score.
5.  **Email Reputation:** Check if the email address `noreply@amazon-security.com` has been reported on email reputation services.

**Deliverable:** A threat enrichment report documenting all findings from the four OSINT tools, including creation dates, reputation scores, and historical abuse reports.

---

### Lab 1.3: PCAP Analysis and Incident Ticket Creation

**Objective:** Analyze network traffic from a phishing compromise and create an incident ticket following the NIST 800-61 framework.

**Scenario:** A user clicked the malicious link. The attacker's malware established a C2 connection and exfiltrated a small amount of data.

**Synthetic PCAP Data (Wireshark Filter Output):**

```
No.     Time        Source          Destination     Protocol Length Info
1       0.000000    192.168.1.100   8.8.8.8         DNS      57     Standard query 0x1234 A amazon-security.com
2       0.050123    192.168.1.100   203.0.113.45    HTTP     234    GET /verify.php?user=admin&pass=... HTTP/1.1
3       0.100456    203.0.113.45    192.168.1.100   HTTP     512    HTTP/1.1 200 OK (HTML response with malware)
4       1.234567    192.168.1.100   198.51.100.50   TCP      54     [SYN] Seq=0 Win=65535
5       1.234890    198.51.100.50   192.168.1.100   TCP      54     [SYN, ACK] Seq=0 Ack=1 Win=65535
6       1.235123    192.168.1.100   198.51.100.50   TCP      54     [ACK] Seq=1 Ack=1 Win=65535
7       1.235456    192.168.1.100   198.51.100.50   HTTP     512    POST /c2/checkin HTTP/1.1 (C2 beacon)
8       2.345678    192.168.1.100   198.51.100.50   HTTP     2048   POST /c2/exfil HTTP/1.1 (Data exfiltration)
9       2.346000    198.51.100.50   192.168.1.100   HTTP     256    HTTP/1.1 200 OK
```

**Lab Steps:**

1.  **Analyze the PCAP:** Trace the events in the synthetic data. Identify the initial DNS query, the malware download, the C2 connection establishment, and the data exfiltration.
2.  **Extract IOCs:** Document all malicious domains, IP addresses, and URLs.
3.  **Create a Timeline:** Order the events chronologically with timestamps.
4.  **Determine the Scope:** Identify the compromised host (`192.168.1.100`).
5.  **Create an Incident Ticket:** Fill out the Incident Ticket Template (provided in the full course documentation) with all findings, including containment and recommended next steps.

**Deliverable:** A completed incident ticket with all IOCs, timeline, and recommended actions.

---

### Portfolio Project 1.1: Phishing Triage Playbook

**Objective:** Create a comprehensive, reusable playbook for phishing triage that can be shared on LinkedIn to demonstrate your IR process.

**Deliverable Structure:**

1.  **Executive Summary:** A one-paragraph overview of the phishing incident, including the attack vector, impact, and resolution.
2.  **Incident Details:** A detailed description of the phishing email, the malicious domain, and the attacker's infrastructure.
3.  **Investigation Process:** A step-by-step walkthrough of how the incident was investigated, including email header analysis, OSINT, and PCAP analysis.
4.  **Key Findings:** A summary of the IOCs, the attack timeline, and the scope of the breach.
5.  **Containment Actions:** A list of the immediate actions taken to contain the threat.
6.  **Recommendations:** A list of long-term recommendations to prevent similar incidents.
7.  **Appendices:** Raw data (email headers, PCAP excerpts, OSINT reports) for reference.

**LinkedIn Presentation Tips:** Write in a clear, professional manner. Use diagrams and tables to visualize the attack chain and timeline. Highlight the key technical skills demonstrated.

---

## Module 5: Malware Attack — Labs and Projects

### Lab 5.1: Static Malware Analysis

**Objective:** Perform static analysis on a malware sample to extract IOCs and determine the malware type.

**Synthetic Malware Sample (Simulated):**

*   **File Name:** `invoice_2024.exe`
*   **MD5 Hash:** `d41d8cd98f00b204e9800998ecf8427e`
*   **SHA-256 Hash:** `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

**Lab Steps:**

1.  **Extract Strings:** Use the `strings` command to extract readable text from the binary. Look for hardcoded IP addresses, URLs, registry keys, or API calls.
    ```bash
    strings invoice_2024.exe | grep -E '(http|\.exe|\.dll|HKEY)'
    ```
    *(Expected output includes: `http://malware-c2.net/beacon`, `C:\Windows\System32\svchost.exe`, `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Run`)*
2.  **Analyze File Metadata:** Use the `file` command and `exiftool` to extract metadata (e.g., compiler, creation date).
    ```bash
    file invoice_2024.exe
    exiftool invoice_2024.exe
    ```
3.  **Calculate Hashes:** Generate MD5, SHA-1, and SHA-256 hashes for reputation checking.
    ```bash
    md5sum invoice_2024.exe
    sha256sum invoice_2024.exe
    ```
4.  **Check VirusTotal:** Paste the hashes into VirusTotal to check if the malware is known. Document the number of detections and the malware family names.
5.  **Extract IOCs:** Document all IOCs found: C2 IP/domain, registry keys, file paths, and API calls.

**Deliverable:** A static analysis report documenting all extracted IOCs and initial malware classification.

---

### Lab 5.2: Memory Forensics with Volatility

**Objective:** Analyze a memory dump from an infected system to identify malicious processes and network connections using the Volatility Framework.

**Synthetic Memory Dump Scenario:** A Windows 10 system was suspected of being infected. A memory dump (`memory.dmp`) was captured.

**Lab Steps:**

1.  **Identify the Operating System:** Use Volatility to determine the OS version and build.
    ```bash
    vol.py -f memory.dmp imageinfo
    ```
2.  **List Running Processes:** Use the `pslist` plugin to list all running processes. Look for suspicious names or parent-child relationships.
    ```bash
    vol.py -f memory.dmp --profile=Win10x64_19041 pslist
    ```
3.  **Analyze Network Connections:** Use the `connscan` plugin to find network connections. Look for connections to the C2 IP (`198.51.100.50`).
    ```bash
    vol.py -f memory.dmp --profile=Win10x64_19041 connscan
    ```
4.  **Identify Injected Code:** Use the `malfind` plugin to find code injection.
    ```bash
    vol.py -f memory.dmp --profile=Win10x64_19041 malfind
    ```
5.  **Extract Suspicious Process:** Dump the suspicious process (e.g., PID 2456) to disk for further analysis.
    ```bash
    vol.py -f memory.dmp --profile=Win10x64_19041 procdump -p 2456 -D ./dump/
    ```

**Deliverable:** A memory forensics report documenting all suspicious processes, network connections, and injected code.

---

### Portfolio Project 5.1: Malware Triage Summary Report

**Objective:** Create a comprehensive malware analysis report suitable for a professional portfolio, synthesizing findings from static, dynamic, and memory analysis.

**Report Structure:**

1.  **Executive Summary:** A one-paragraph overview of the malware, its threat level, and key findings.
2.  **File Information:** Hash values, file size, file type, and compilation date.
3.  **Static Analysis Findings:** Extracted strings, metadata, and initial IOCs.
4.  **Dynamic Analysis Findings:** Behavioral observations from sandbox execution.
5.  **Memory Forensics Findings:** Suspicious processes, injected code, and network connections from memory analysis.
6.  **Malware Family Classification:** Identification of the malware family and comparison with known variants.
7.  **MITRE ATT&CK Mapping:** Mapping of observed behaviors to MITRE ATT&CK tactics and techniques.
8.  **Threat Assessment:** Severity rating, impact assessment, and affected systems.
9.  **Recommendations:** Containment, eradication, and prevention recommendations.
10. **Appendices:** Raw data (strings output, memory dump excerpts, PCAP data) for reference.

---

## Module 6: Detection Engineering — Labs and Projects

### Lab 6.1: Suricata Rule Creation and Testing

**Objective:** Write a Suricata rule to detect a specific attack pattern and test it against a PCAP file.

**Attack Pattern to Detect:** HTTP requests to known malicious domains (e.g., `malware-c2.net`).

**Suricata Rule:**

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Potential Malware C2 Communication";
    flow:to_server,established;
    content:"GET"; http_method;
    content:"malware-c2.net"; http_host;
    sid:1000001; rev:1; classtype:trojan-activity; priority:1;
)
```

**Lab Steps:**

1.  **Create the Rule File:** Save the rule to a file named `malware-c2.rules`.
2.  **Create a Test PCAP:** Use a tool like `scapy` (Python) to create a PCAP file containing HTTP traffic to "malware-c2.net".
3.  **Run Suricata:** Execute Suricata against the test PCAP using the rule file.
    ```bash
    suricata -r test.pcap -S malware-c2.rules -l ./logs/
    ```
4.  **Verify the Alert:** Check the alert log (`eve.json`) to confirm the rule triggered.
    ```bash
    cat ./logs/eve.json | grep "malware-c2.net"
    ```
5.  **Tune the Rule:** Adjust the rule to reduce false positives (e.g., add additional conditions).

**Deliverable:** A documented Suricata rule with test results and tuning notes.

---

### Lab 6.2: YARA Rule Creation and Malware Detection

**Objective:** Write a YARA rule to detect a specific malware family (e.g., "CryptoLocker-like" ransomware) and test it against known samples.

**YARA Rule:**

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

**Lab Steps:**

1.  **Create the Rule File:** Save the rule to a file named `cryptolocker.yar`.
2.  **Create Test Malware Samples:** Use synthetic or known samples of the target malware family.
3.  **Run YARA:** Scan files or directories with the YARA rule.
    ```bash
    yara cryptolocker.yar /path/to/samples/
    ```
4.  **Verify Detections:** Check the output for matches.
5.  **Test for False Positives:** Scan benign files to ensure the rule doesn't produce false positives.

**Deliverable:** A documented YARA rule with test results and false positive analysis.

---

### Portfolio Project 6.1: Detection Rule Pack v1

**Objective:** Create a set of 5 detection rules (Suricata, YARA, or Sigma) for a specific threat (e.g., APT-style lateral movement using PsExec).

**Rule Set Components:**

1.  **Suricata Rule:** Detect PsExec traffic (port 445 with specific SMB signatures).
2.  **Suricata Rule:** Detect suspicious PowerShell execution over the network.
3.  **YARA Rule:** Detect PsExec binary by file signature.
4.  **Sigma Rule:** Detect Windows Event Log entries for service creation (lateral movement indicator).
5.  **Sigma Rule:** Detect unusual process execution patterns (parent-child relationships).

**Deliverable Structure:**

*   A documented rule pack with all 5 rules.
*   Test cases for each rule (PCAP files, malware samples, log entries).
*   Test results showing successful detections and false positive analysis.
*   A brief explanation of how these rules work together to detect lateral movement.

---

## Module 7: Live Attack & Defense — Capstone Challenges

### Capstone Lab 7.1: Multi-Stage Attack Simulation

**Objective:** Analyze a complete, multi-stage attack scenario and perform end-to-end incident response.

**Attack Scenario:** Phishing email → Malicious Excel macro → PowerShell execution → C2 establishment → Reconnaissance → Privilege escalation → Data exfiltration.

**Provided Data (Simulated):** Phishing email (raw), Malicious Excel file (for static analysis), Network traffic capture (PCAP), Host logs (Windows Event Log and Syslog), AWS CloudTrail logs, Memory dump.

**Lab Steps (NIST 800-61 Phases):**

1.  **Phase 1: Detection & Analysis**
    *   Analyze the phishing email and Excel file (static analysis).
    *   Analyze the PCAP to identify the C2 communication and data exfiltration.
    *   Review host logs and CloudTrail to identify the attack timeline and scope.
2.  **Phase 2: Containment**
    *   Identify the compromised host and user account.
    *   Recommend immediate containment actions (isolate host, disable account, block C2 IP).
3.  **Phase 3: Eradication & Recovery**
    *   Identify all persistence mechanisms (scheduled tasks, registry modifications).
    *   Recommend eradication steps (remove malware, reset credentials, patch vulnerabilities).
    *   Recommend recovery steps (restore from backup, rebuild system).
4.  **Phase 4: Post-Incident**
    *   Create a comprehensive incident report with timeline, findings, and recommendations.
    *   Identify lessons learned and recommendations for preventing similar incidents.

**Deliverable:** A comprehensive incident report (10-15 pages) documenting all phases of the incident response.

---

### Capstone Project 7.1: Full Incident Report with Timeline

**Objective:** Create a professional, LinkedIn-ready incident report documenting a complete incident.

**Report Structure:**

1.  **Executive Summary:** A one-page overview suitable for C-level executives.
2.  **Incident Details:** Complete description of the attack, including timeline, scope, and impact.
3.  **Investigation Findings:** Detailed technical findings from each phase of the investigation.
4.  **Root Cause Analysis:** Explanation of how the attack succeeded and what vulnerabilities were exploited.
5.  **Impact Assessment:** Quantification of the impact (systems affected, data accessed, downtime).
6.  **Containment Actions:** Detailed description of actions taken to stop the attack.
7.  **Eradication & Recovery:** Steps taken to remove the attacker's presence and restore systems.
8.  **Lessons Learned:** Recommendations for preventing similar incidents.
9.  **Appendices:** Raw data (logs, PCAP excerpts, screenshots) for reference.

---

### Capstone Challenge 7.2: Detect & Defend Challenge (Timed)

**Objective:** Develop detection logic, investigate suspicious activity, and generate a SOC-ready report under time pressure.

**Challenge Format (2 Hours Total):**

1.  **Detection Development (30 minutes):** Write 2-3 detection rules (Suricata, YARA, or Sigma) to detect the attack pattern.
2.  **Investigation (60 minutes):** Analyze provided logs (PCAP, host logs, cloud logs) to identify the attack, create a timeline, and determine the scope.
3.  **Reporting (30 minutes):** Create a one-page incident summary suitable for management, including the current status, affected systems, and recommended immediate actions.

**Deliverable:** Detection rules, investigation notes, and executive incident summary.

---

## Synthetic Data Examples (For Lab Use)

### Synthetic Suricata Alert Log (eve.json format)

```json
{
  "timestamp": "2024-01-15T10:32:45.123456+0000",
  "flow_id": 1234567890,
  "event_type": "alert",
  "src_ip": "192.168.1.100",
  "src_port": 49152,
  "dest_ip": "198.51.100.50",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "alert",
    "gid": 1,
    "signature_id": 1000001,
    "signature": "Potential Malware C2 Communication",
    "category": "Trojan activity",
    "severity": 1
  },
  "http": {
    "hostname": "malware-c2.net",
    "url": "/beacon",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 512
  }
}
```

### Synthetic YARA Detection Output

```
CryptoLocker_Variant /tmp/samples/malware_001.exe
CryptoLocker_Variant /tmp/samples/malware_002.exe
PsExec_Lateral_Movement /tmp/samples/psexec.exe
```
