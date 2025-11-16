# SOC Analyst I — From Cradle to Grave: Full Course Content

## Course Description

This is a practical, intensive, 8-module cybersecurity course designed to transform an aspiring professional into a job-ready Security Operations Center (SOC) Analyst I. Titled "SOC Analyst I — From Cradle to Grave," the course focuses on real-world incident response, detection engineering, and threat hunting across modern hybrid environments (Windows, Linux, and AWS Cloud). The curriculum is structured around the 8 most common and critical attack types a Tier 1 SOC analyst will face, providing a hands-on, portfolio-building experience.

The course is specifically tailored for a visual learner who works long hours and needs a highly structured, efficient study plan. It emphasizes open-source tools, AI-augmented SOC workflows, and career progression toward Tier 2 and Cloud Security Analyst roles. By the end of this course, the learner will possess the practical skills, portfolio projects, and interview confidence to secure their first SOC role.

## Learner Profile Summary

| Characteristic | Detail |
| :--- | :--- |
| **Learning Style** | Visual learner; prefers videos, diagrams, guided walkthroughs, and hands-on labs. |
| **Schedule** | Works 10-hour shifts; studies primarily at night; requires a highly optimized study schedule. |
| **Experience** | Growing experience with Linux, AWS cloud security, ticketing, IR, OSINT, PCAP, and malware fundamentals. |
| **Career Goal** | Progression from SOC Tier 1 → Tier 2 → Cloud Security Analyst; wants a job within 6 months. |
| **Key Interests** | AI automation, Linux security, PCAP/NetFlow analysis, threat hunting, and building a professional portfolio. |
| **Tool Preference** | Open-source tools only (no paid platforms); strong desire to integrate AI for automation. |

## Course Goals and Learning Objectives

Upon completion of this course, the learner will be able to:

1.  **Handle Tier 1 SOC Tickets** end-to-end, following established Incident Response (IR) workflows like NIST 800-61.
2.  **Perform Triage** on the 8 core incident types: Phishing, Unauthorized Access, Data Loss, DDoS, Malware, Detection Engineering, Live Attack Defense, and Career Assessment.
3.  **Conduct Deep-Dive Investigations** using essential SOC tools for email header analysis, host log analysis (Linux/Windows), memory forensics, and network traffic (PCAP/NetFlow) analysis.
4.  **Operate in Hybrid Environments**, specifically investigating logs and alerts from AWS (CloudTrail, GuardDuty, VPC Flow Logs) alongside traditional on-premise systems.
5.  **Develop Detection Logic** by creating and testing rules using industry-standard tools like Suricata (IDS/IPS), YARA (Malware Signatures), and Sigma (Generic SIEM Rules).
6.  **Create a Professional Portfolio** by completing at least 16 LinkedIn-ready projects, including IR reports, playbooks, and detection rule packs.
7.  **Master SOC Documentation** by utilizing templates for incident reports, phishing response, and malware analysis summaries.
8.  **Pass SOC Interviews** with confidence, having practiced technical and behavioral questions, and whiteboard-style IR scenarios.

## Full 8-Module Course Outline

The course is structured into 8 intensive modules, each focusing on a critical SOC function or attack type.

### Module 1: Phishing Attack — The Gateway Incident

| Topic | Key Learning Assets | Hands-On Labs & Projects |
| :--- | :--- | :--- |
| **Phishing Triage Workflow** | IR Checklist, Phishing Response Template | Email Header Investigation Lab, OSINT Walkthrough (Domain/IP), Ticketing Simulation (NIST 800-61) |
| **Email Header Analysis** | Header Field Cheat Sheet, Key Linux Commands | Lab: Identifying Malicious Links and Attachments |
| **OSINT for Threat Enrichment** | VirusTotal, AbuseIPDB, Whois, Shodan Walkthroughs | Project: "Phishing Triage Playbook" (LinkedIn-ready) |
| **PCAP Analysis of Exfil Attempts** | Wireshark Filters Cheat Sheet | Lab: Analyzing Network Traffic for Phishing Post-Compromise |
| **Secretary Summary** | Concise summary of Phishing Triage and Reporting | Quiz: Phishing Indicators of Compromise (IOCs) |

### Module 2: Unauthorized Access — The Insider & External Threat

| Topic | Key Learning Assets | Hands-On Labs & Projects |
| :--- | :--- | :--- |
| **IAM Abuse & Privilege Escalation** | AWS IAM Policy Investigation Workflow, Linux Permissions Diagram | Lab: Investigating Failed Login Attempts (Linux `auth.log` and AWS CloudTrail) |
| **Host Log Analysis** | Linux `journalctl` and Windows Event Log (Security) Commands | Lab: User Activity Timeline Creation from Host Logs |
| **Lateral Movement Detection** | Network Traffic Review Workflow, Common Attacker Tools | Lab: Detecting SSH Brute Force and Suspicious File Transfers |
| **Cloud-Specific Unauthorized Access** | AWS GuardDuty Alerts, S3 Bucket Misconfiguration | Project: "Unauthorized Access IR Report" (Full Incident Report) |
| **Secretary Summary** | Concise summary of Unauthorized Access Indicators and Response | Quiz: IAM and Log Analysis Fundamentals |

### Module 3: Data Loss / Exfiltration — Protecting the Crown Jewels

| Topic | Key Learning Assets | Hands-On Labs & Projects |
| :--- | :--- | :--- |
| **Data Exfiltration Patterns** | Common Exfil Techniques (DNS Tunneling, Cloud Storage) | Lab: Detecting Large File Transfers in VPC Flow Logs |
| **File Transfer Protocol Analysis** | FTP, SFTP, and HTTP POST Analysis in PCAP | Lab: Analyzing Network Traffic for Encrypted Data Exfil |
| **Cloud Data Movement Forensics** | AWS S3 Access Logs and CloudTrail `GetObject`/`PutObject` Analysis | Lab: Investigating S3 Exfil Detection Patterns |
| **Linux Disk / Directory Forensics** | SleuthKit/Autopsy Introduction, Key Linux Forensic Commands | Project: "Data Exfil Detection Blueprint" (Detection Rule Set) |
| **Secretary Summary** | Concise summary of Data Loss Prevention (DLP) and Response | Quiz: Data Exfil Techniques and Log Sources |

### Module 4: DDoS Attack — Availability and Resilience

| Topic | Key Learning Assets | Hands-On Labs & Projects |
| :--- | :--- | :--- |
| **DDoS Attack Types & Signatures** | Layer 3/4 (SYN Flood, UDP Flood) vs. Layer 7 (HTTP Flood) | Lab: Identifying Botnet Traffic Patterns in NetFlow Data |
| **Rate-Based Detection Logic** | Threshold Setting and Alert Tuning Workflow | Lab: Creating a Simple Rate-Limit Alert in a SIEM-like environment |
| **Network Forensics for DDoS** | Analyzing High-Volume PCAP Files, Identifying Source IPs | Lab: Tracing a DDoS Attack Back to its Originating Network |
| **Cloud Mitigation Strategies** | AWS Shield, CloudFront, and WAF Configuration Basics | Project: "DDoS Triage Workflow" (Step-by-step mitigation plan) |
| **Secretary Summary** | Concise summary of DDoS Detection, Triage, and Mitigation | Quiz: DDoS Mitigation Techniques |

### Module 5: Malware Attack — The Hostile Takeover

| Topic | Key Learning Assets | Hands-On Labs & Projects |
| :--- | :--- | :--- |
| **Malware Triage Workflow** | Malware Triage Checklist, Sandbox Analysis Workflow | Lab: Static Analysis (Strings, Hashes, File Metadata) |
| **Dynamic Analysis (Safe Environment)** | Introduction to Sandboxing and Behavioral Analysis | Lab: Dynamic Analysis Walkthrough (Observing File System/Registry Changes) |
| **Memory Forensics** | Volatility Framework Introduction, Key Commands (`pslist`, `connscan`) | Lab: Identifying Malicious Processes and Network Connections in a Memory Dump |
| **Reverse Engineering Basics** | Introduction to Disassemblers (Ghidra/IDA Free), Malware Family Identification | Project: "Malware Triage Summary Report" (Full Analysis Report) |
| **Secretary Summary** | Concise summary of Malware Lifecycle and Analysis Techniques | Quiz: Memory Forensics and Malware Indicators |

### Module 6: Detection Engineering — Building the Defenses

| Topic | Key Learning Assets | Hands-On Labs & Projects |
| :--- | :--- | :--- |
| **Introduction to Detection Engineering** | The Detection Lifecycle (Identify, Develop, Test, Deploy, Tune) | Lab: Writing a Basic Suricata Rule (e.g., detecting a specific HTTP header) |
| **Suricata Rule Creation** | Rule Syntax Cheat Sheet, Common Keywords (content, flow, sid) | Lab: Testing and Tuning a Suricata Rule against synthetic traffic |
| **YARA Rule Creation** | YARA Rule Syntax, Metadata, and String Matching | Lab: Writing a YARA Rule to detect a specific malware sample |
| **Sigma Rule Creation** | Introduction to Sigma, Converting Sigma to SIEM Queries | Project: "Detection Rule Pack v1" (A set of 5 rules for a specific threat) |
| **Secretary Summary** | Concise summary of Detection Engineering Principles and Tools | Quiz: Rule Syntax and Logic |

### Module 7: Live Attack & Defense — The Capstone Simulation

| Topic | Key Learning Assets | Hands-On Labs & Projects |
| :--- | :--- | :--- |
| **Multi-Stage Attack Simulation** | Attack Chain Diagram (e.g., MITRE ATT&CK Mapping) | Capstone Lab: Full Incident Response on a Simulated Multi-Stage Attack |
| **Live Triage and Containment** | Containment Checklist, Communication Workflow | Lab: Performing Live Containment and Eradication Steps |
| **Timeline Building and Reporting** | Timeline Creation Template, Executive Summary Writing | Project: "10-Minute Incident Summary Challenge" (Rapid Reporting) |
| **Full Incident Report Creation** | NIST 800-61 Steps Review | Capstone Project: Full Incident Report w/ Timeline (The ultimate portfolio piece) |
| **Secretary Summary** | Concise summary of the Incident Response Process and Best Practices | Challenge: Detect & Defend Challenge (Build logic, investigate, report) |

### Module 8: SOC Interview Simulation — Career Readiness

| Topic | Key Learning Assets | Hands-On Labs & Projects |
| :--- | :--- | :--- |
| **Technical Mock Interview** | 45-Minute Mock Interview Script (30 Questions) | Lab: Whiteboard-Style IR Scenario Walkthrough |
| **Behavioral Interview Prep** | STAR Method Guide, Common Behavioral Questions | Project: Resume and LinkedIn Optimization Checklist |
| **Career Roadmap** | 90-Day Study Plan, 6-Month SOC Career Roadmap (Tier 1 → Tier 2) | Assessment: Final Course Quiz and Self-Assessment |
| **Final Assessment** | Review of all portfolio projects and final course summary | Deliverable: Personalized Career Action Plan |
| **Secretary Summary** | Concise summary of key career advice and next steps | Final Course Wrap-up and Next Steps |


---

## Detailed Daily Lesson Plans (1–2 Hour Study Blocks)

### Module 1: Phishing Attack — Daily Lesson Plan

**Study Duration:** 2 hours per session (recommended: 3 sessions total)

**Session 1.1: Phishing Fundamentals and Email Header Analysis (60 minutes)**

This session introduces the learner to the most common attack vector in SOC environments: phishing. The learner will understand the anatomy of a phishing email, how to extract and analyze email headers, and how to identify malicious indicators.

**Key Topics Covered:**

The session begins with an overview of phishing as a social engineering attack. Phishing emails are designed to trick users into revealing sensitive information, clicking malicious links, or downloading infected attachments. In a typical SOC environment, phishing emails represent approximately 80% of all initial compromise vectors. The learner will be introduced to the concept of the "phishing kill chain," which consists of five stages: reconnaissance, weaponization, delivery, exploitation, and post-compromise activity.

Email headers contain critical metadata that can reveal the true origin of an email, the servers it passed through, and potential indicators of compromise. The learner will learn to extract headers from common email clients (Outlook, Gmail) and analyze key fields such as `From`, `To`, `Subject`, `Date`, `Message-ID`, `Received`, `Return-Path`, and `X-Originating-IP`. Each field provides a clue about the email's authenticity.

**Practical Walkthrough:**

The learner will be provided with a sample phishing email header and will perform a step-by-step analysis. They will identify the sender's claimed domain, verify it against the actual sending server, check for SPF/DKIM/DMARC failures, and trace the email's path through multiple mail servers. This hands-on exercise will take approximately 30 minutes and will use real-world examples from public phishing databases.

**Key Takeaways:**

By the end of this session, the learner will understand the structure of email headers, be able to identify common phishing indicators (domain spoofing, suspicious IP addresses, missing authentication), and know how to extract and preserve email headers for investigation.

**Secretary-Style Summary:**

Phishing emails are the primary entry point for attackers. Email headers contain metadata that reveals the true sender and path. Key fields to analyze: `From`, `Received`, `Return-Path`, and authentication headers (`SPF`, `DKIM`, `DMARC`). Always verify the sender's domain against the sending server's IP address. Preserve headers in their raw format for investigation.

---

**Session 1.2: OSINT for Threat Enrichment (60 minutes)**

This session teaches the learner how to use open-source intelligence (OSINT) tools to enrich phishing investigations with threat intelligence.

**Key Topics Covered:**

The learner will be introduced to the concept of threat enrichment, which is the process of adding contextual information to an indicator of compromise (IOC) such as an IP address, domain, or file hash. Threat enrichment helps the SOC analyst determine the severity of an incident and identify patterns across multiple attacks.

The session will cover four essential OSINT tools: VirusTotal (for file and domain reputation), AbuseIPDB (for IP reputation), Whois (for domain registration information), and Shodan (for identifying exposed services). Each tool will be demonstrated with real-world examples.

**Practical Walkthrough:**

The learner will be given a suspicious domain from a phishing email and will perform a complete OSINT investigation. They will check the domain's reputation on VirusTotal, look up the registrant information using Whois, identify the hosting provider using Shodan, and check if the domain's IP address has been reported for abuse on AbuseIPDB. This investigation will take approximately 40 minutes and will result in a comprehensive threat profile.

**Key Takeaways:**

By the end of this session, the learner will be able to use OSINT tools to enrich phishing investigations, understand how to interpret threat intelligence reports, and know when to escalate a phishing incident based on the severity of the threat.

**Secretary-Style Summary:**

Threat enrichment adds context to IOCs. Key OSINT tools: VirusTotal (reputation), AbuseIPDB (IP abuse reports), Whois (domain registration), Shodan (exposed services). Always check multiple sources before concluding that a domain is malicious. Document all findings in the incident ticket for future reference.

---

**Session 1.3: PCAP Analysis and Ticketing Simulation (60 minutes)**

This session teaches the learner how to analyze network traffic (PCAP files) for signs of post-compromise phishing activity and how to create a proper incident ticket following NIST 800-61 guidelines.

**Key Topics Covered:**

After a user clicks a malicious link or downloads an infected attachment, the attacker may establish a command-and-control (C2) connection or exfiltrate data. The learner will learn to analyze PCAP files using Wireshark, a network protocol analyzer, to identify suspicious traffic patterns such as DNS queries to known malicious domains, HTTP requests to suspicious IP addresses, or unusual port usage.

The session will also introduce the learner to the NIST 800-61 incident response framework, which provides a structured approach to handling security incidents. The learner will learn the four phases of incident response: preparation, detection and analysis, containment/eradication/recovery, and post-incident activities.

**Practical Walkthrough:**

The learner will be given a PCAP file from a phishing incident and will use Wireshark to identify suspicious traffic. They will filter for DNS queries, HTTP requests, and other protocols, and will identify the attacker's C2 server. They will then create an incident ticket using a provided template, documenting all findings and following the NIST 800-61 framework. This exercise will take approximately 50 minutes.

**Key Takeaways:**

By the end of this session, the learner will be able to analyze PCAP files for indicators of compromise, understand the NIST 800-61 incident response framework, and create a professional incident ticket that clearly documents the investigation and recommended actions.

**Secretary-Style Summary:**

PCAP analysis reveals post-compromise activity. Use Wireshark to filter for DNS, HTTP, and other protocols. Look for connections to known malicious IPs or domains. Create incident tickets following NIST 800-61: Preparation, Detection & Analysis, Containment/Eradication/Recovery, Post-Incident. Always document findings with evidence and timestamps.

---

### Module 2: Unauthorized Access — Daily Lesson Plan

**Study Duration:** 2 hours per session (recommended: 3 sessions total)

**Session 2.1: IAM Abuse and Privilege Escalation (60 minutes)**

This session introduces the learner to unauthorized access incidents, focusing on Identity and Access Management (IAM) abuse and privilege escalation attacks.

**Key Topics Covered:**

Unauthorized access incidents occur when an attacker gains access to a user account or system without proper authorization. This can happen through credential theft, weak passwords, or exploitation of vulnerabilities. The learner will understand the difference between external attackers (who compromise credentials) and insider threats (who abuse their own credentials).

The session will cover common privilege escalation techniques on both Linux and Windows systems, including exploiting weak file permissions, abusing sudo configurations, and leveraging Windows UAC bypass techniques. The learner will also learn about AWS IAM abuse, such as creating unauthorized access keys or modifying IAM policies to maintain persistence.

**Practical Walkthrough:**

The learner will be given a scenario where a user account has been compromised. They will examine the host logs (Linux `auth.log` and Windows Event Log) to identify the attacker's activities, such as failed login attempts, successful logins from unusual locations, and privilege escalation attempts. They will also examine AWS CloudTrail logs to identify suspicious IAM activities. This exercise will take approximately 45 minutes.

**Key Takeaways:**

By the end of this session, the learner will understand common unauthorized access attack vectors, be able to analyze host logs to identify suspicious activity, and know how to detect IAM abuse in cloud environments.

**Secretary-Style Summary:**

Unauthorized access often starts with credential theft. Key indicators: failed login attempts, successful logins from unusual locations, privilege escalation attempts, and creation of new user accounts. Check Linux `auth.log`, Windows Event Log (Security), and AWS CloudTrail for evidence. Correlate multiple log sources to build a complete picture of the attack.

---

**Session 2.2: Host Log Analysis and User Activity Timeline (60 minutes)**

This session teaches the learner how to perform deep-dive host log analysis to understand an attacker's activities and create a timeline of events.

**Key Topics Covered:**

Host logs are the primary source of information for understanding what happened on a compromised system. The learner will learn to analyze Linux logs (stored in `/var/log/`) and Windows Event Logs (accessed through Event Viewer or PowerShell). Key log sources include `auth.log` (authentication attempts), `syslog` (system events), `journalctl` (systemd logs), and Windows Security Event Log (event ID 4624 for successful logins, 4625 for failed logins).

The learner will also learn about the concept of a user activity timeline, which is a chronological record of all actions taken by a user or attacker on a system. This timeline is critical for understanding the scope and impact of an incident.

**Practical Walkthrough:**

The learner will be given a set of host logs from a compromised Linux system. They will extract relevant log entries, parse them to identify key events (logins, file modifications, process executions), and create a timeline of the attacker's activities. They will use tools like `grep`, `awk`, and `sed` to filter and process log data. This exercise will take approximately 50 minutes and will result in a comprehensive timeline document.

**Key Takeaways:**

By the end of this session, the learner will be able to analyze host logs using command-line tools, create a user activity timeline, and identify the attacker's actions and objectives.

**Secretary-Style Summary:**

Host logs reveal what happened on a system. Key Linux logs: `/var/log/auth.log` (authentication), `/var/log/syslog` (system events), `journalctl` (systemd logs). Key Windows logs: Security Event Log (event IDs 4624, 4625, 4688). Create a timeline by extracting relevant events and sorting by timestamp. Use command-line tools (`grep`, `awk`, `sed`) to filter large log files.

---

**Session 2.3: Cloud IAM Investigation and Lateral Movement Detection (60 minutes)**

This session teaches the learner how to investigate unauthorized access in cloud environments and detect lateral movement across systems.

**Key Topics Covered:**

In cloud environments like AWS, unauthorized access can take many forms: compromised IAM credentials, exposed access keys, misconfigured S3 buckets, and abuse of temporary security credentials. The learner will learn to analyze AWS CloudTrail logs, which record all API calls made to AWS services, and AWS GuardDuty alerts, which automatically detect suspicious activity.

The session will also cover lateral movement detection, which is the process of identifying when an attacker moves from one system to another within a network. Common lateral movement techniques include SSH key theft, pass-the-hash attacks, and exploitation of trust relationships between systems.

**Practical Walkthrough:**

The learner will be given a scenario where an IAM user's access keys have been compromised. They will examine AWS CloudTrail logs to identify the attacker's API calls, determine what resources were accessed, and identify any unauthorized changes. They will also examine network logs (VPC Flow Logs) to identify lateral movement attempts. This exercise will take approximately 50 minutes.

**Key Takeaways:**

By the end of this session, the learner will understand how to investigate unauthorized access in cloud environments, be able to analyze CloudTrail logs, and know how to detect lateral movement using network logs.

**Secretary-Style Summary:**

Cloud unauthorized access indicators: new IAM access keys, API calls from unusual locations, S3 bucket access from external IPs, and GuardDuty alerts. Check CloudTrail for `CreateAccessKey`, `AttachUserPolicy`, and `GetObject` API calls. Examine VPC Flow Logs for lateral movement (SSH, RDP, WinRM traffic between systems). Correlate cloud and network logs for complete picture.

---

### Module 3: Data Loss / Exfiltration — Daily Lesson Plan

**Study Duration:** 2 hours per session (recommended: 3 sessions total)

**Session 3.1: Data Exfiltration Patterns and Detection (60 minutes)**

This session introduces the learner to data loss incidents, focusing on identifying and analyzing data exfiltration patterns.

**Key Topics Covered:**

Data exfiltration is the unauthorized transfer of sensitive data outside of the organization. This can happen through various channels: cloud storage services (Dropbox, Google Drive), file transfer protocols (FTP, SFTP), DNS tunneling, or encrypted channels. The learner will understand the concept of data loss prevention (DLP) and the indicators of compromise (IOCs) that suggest data exfiltration.

The session will cover common exfiltration techniques, including large file transfers to external IP addresses, unusual DNS queries (which may indicate DNS tunneling), and access to cloud storage services from internal systems. The learner will also learn about the concept of "beaconing," where an attacker establishes a persistent connection to exfiltrate data over time.

**Practical Walkthrough:**

The learner will be given a network traffic capture (PCAP file) from a system suspected of exfiltrating data. They will use Wireshark to identify large file transfers, analyze DNS queries for signs of tunneling, and identify connections to cloud storage services. They will also examine network flow logs (NetFlow or sFlow data) to identify high-volume data transfers. This exercise will take approximately 45 minutes.

**Key Takeaways:**

By the end of this session, the learner will be able to identify data exfiltration patterns in network traffic, understand common exfiltration techniques, and know how to analyze network logs to detect data loss incidents.

**Secretary-Style Summary:**

Data exfiltration indicators: large file transfers to external IPs, unusual DNS queries (DNS tunneling), access to cloud storage services, and high-volume data transfers. Check PCAP files for FTP/SFTP traffic, HTTP POST requests with large payloads, and encrypted tunnels. Analyze NetFlow data for volume anomalies. Correlate multiple data sources to confirm exfiltration.

---

**Session 3.2: File Transfer Protocol Analysis and Cloud Data Forensics (60 minutes)**

This session teaches the learner how to analyze file transfer protocols and investigate data exfiltration in cloud environments.

**Key Topics Covered:**

File transfer protocols such as FTP, SFTP, and HTTP are commonly used for data exfiltration. The learner will learn to analyze PCAP files to identify these protocols, extract file names and sizes, and determine the destination of the transfer. The session will also cover cloud-specific data exfiltration, such as unauthorized access to S3 buckets or excessive downloads of data from cloud storage.

The learner will understand how to analyze AWS S3 access logs and CloudTrail logs to identify suspicious data access patterns, such as `GetObject` calls from unusual IP addresses or large numbers of `ListBucket` calls that may indicate reconnaissance.

**Practical Walkthrough:**

The learner will be given a PCAP file containing FTP traffic and will extract the file names and sizes being transferred. They will also be given AWS S3 access logs and will identify suspicious access patterns. This exercise will take approximately 50 minutes and will result in a comprehensive analysis of the data exfiltration.

**Key Takeaways:**

By the end of this session, the learner will be able to analyze file transfer protocols in PCAP files, extract file information, and investigate data exfiltration in cloud environments.

**Secretary-Style Summary:**

File transfer analysis: identify FTP/SFTP traffic in PCAP, extract file names and sizes, determine destination. Cloud data forensics: check S3 access logs for `GetObject` calls from unusual IPs, analyze CloudTrail for `ListBucket` and `GetObject` API calls, identify excessive data downloads. Correlate access logs with user accounts to identify insider threats.

---

**Session 3.3: Linux Disk Forensics and Data Loss Prevention (60 minutes)**

This session teaches the learner how to perform disk forensics on Linux systems to identify data exfiltration and implement data loss prevention strategies.

**Key Topics Covered:**

When data is exfiltrated, evidence remains on the system's disk. The learner will learn to use forensic tools such as SleuthKit (a collection of command-line tools) and Autopsy (a GUI-based forensic platform) to analyze disk images and recover deleted files. The session will also cover Linux-specific forensics, such as analyzing the file system journal to identify file deletion timestamps and recovering deleted files.

The learner will also understand the concept of data loss prevention (DLP), which involves identifying sensitive data, monitoring its access and movement, and preventing unauthorized exfiltration.

**Practical Walkthrough:**

The learner will be given a disk image from a compromised Linux system and will use SleuthKit tools to analyze the file system, identify recently modified or deleted files, and recover deleted files that may contain evidence of exfiltration. This exercise will take approximately 50 minutes.

**Key Takeaways:**

By the end of this session, the learner will be able to perform disk forensics on Linux systems, recover deleted files, and understand how to implement data loss prevention strategies.

**Secretary-Style Summary:**

Linux disk forensics: use SleuthKit tools (`fls`, `icat`, `istat`) to analyze file systems, identify deleted files, and recover data. Check file access times (atime, mtime, ctime) to identify when files were accessed or modified. Analyze file system journal for deletion timestamps. Implement DLP by monitoring sensitive data access and preventing unauthorized transfers.

---

### Module 4: DDoS Attack — Daily Lesson Plan

**Study Duration:** 2 hours per session (recommended: 2 sessions total)

**Session 4.1: DDoS Attack Types and Detection (60 minutes)**

This session introduces the learner to Distributed Denial of Service (DDoS) attacks and how to detect them using network analysis.

**Key Topics Covered:**

A DDoS attack is an attempt to make a service unavailable by overwhelming it with traffic from multiple sources. The learner will understand the different types of DDoS attacks: Layer 3/4 attacks (SYN floods, UDP floods) that target network infrastructure, and Layer 7 attacks (HTTP floods, DNS amplification) that target application services.

The session will cover the concept of a botnet, which is a network of compromised computers (bots) controlled by an attacker. Botnets are used to launch large-scale DDoS attacks. The learner will understand how to identify botnet traffic in network logs by looking for patterns such as synchronized traffic from multiple sources, unusual port usage, and high-volume connections.

**Practical Walkthrough:**

The learner will be given a network traffic capture containing DDoS traffic and will use Wireshark to identify the attack. They will analyze the traffic patterns, identify the source IPs, and determine the type of DDoS attack (SYN flood, UDP flood, HTTP flood, etc.). This exercise will take approximately 45 minutes.

**Key Takeaways:**

By the end of this session, the learner will understand different types of DDoS attacks, be able to identify DDoS traffic in network captures, and know how to classify attacks by type.

**Secretary-Style Summary:**

DDoS attack types: Layer 3/4 (SYN floods, UDP floods) attack infrastructure; Layer 7 (HTTP floods, DNS amplification) attack applications. Botnet indicators: synchronized traffic from multiple sources, unusual ports, high-volume connections. Identify DDoS in PCAP by analyzing packet patterns, source IPs, and traffic volume. Use Wireshark filters to isolate attack traffic.

---

**Session 4.2: DDoS Mitigation and Cloud-Based Defenses (60 minutes)**

This session teaches the learner how to mitigate DDoS attacks and implement cloud-based defense strategies.

**Key Topics Covered:**

DDoS mitigation involves multiple strategies: rate limiting (restricting the number of requests from a source), traffic filtering (blocking traffic from known malicious sources), and traffic scrubbing (routing traffic through a service that filters malicious traffic). The learner will understand how to implement these strategies using network devices and cloud services.

The session will also cover AWS-specific DDoS mitigation services, such as AWS Shield (which provides automatic DDoS protection), AWS WAF (Web Application Firewall), and CloudFront (which can distribute traffic and absorb attacks). The learner will understand how to configure these services and monitor their effectiveness.

**Practical Walkthrough:**

The learner will be given a DDoS scenario and will develop a mitigation strategy. They will determine the appropriate rate limits, identify traffic patterns to filter, and configure AWS Shield and WAF rules. They will also analyze NetFlow data to monitor the effectiveness of their mitigation. This exercise will take approximately 50 minutes.

**Key Takeaways:**

By the end of this session, the learner will understand DDoS mitigation strategies, be able to configure cloud-based defenses, and know how to monitor and tune DDoS protection systems.

**Secretary-Style Summary:**

DDoS mitigation: rate limiting (restrict requests per source), traffic filtering (block known malicious IPs), traffic scrubbing (route through filtering service). AWS defenses: Shield (automatic protection), WAF (application-level filtering), CloudFront (traffic distribution). Monitor effectiveness using NetFlow data and CloudWatch metrics. Tune thresholds to balance protection and legitimate traffic.

---

### Module 5: Malware Attack — Daily Lesson Plan

**Study Duration:** 2 hours per session (recommended: 4 sessions total)

**Session 5.1: Malware Triage and Static Analysis (60 minutes)**

This session introduces the learner to malware analysis, focusing on static analysis techniques that can be performed without executing the malware.

**Key Topics Covered:**

Malware is malicious software designed to harm a system or steal data. The learner will understand the different types of malware: viruses (self-replicating), worms (self-propagating), trojans (disguised as legitimate software), ransomware (encrypts data for ransom), and spyware (steals information).

Static analysis involves examining the malware without executing it. The learner will learn to extract strings from the malware binary (which may reveal hardcoded IP addresses, URLs, or commands), analyze the file metadata (which may reveal the compiler used or the original file name), and calculate file hashes (which can be used to identify known malware).

**Practical Walkthrough:**

The learner will be given a malware sample and will perform static analysis. They will use command-line tools like `strings`, `file`, and `md5sum` to extract information from the malware. They will also use online services like VirusTotal to check if the malware is known. This exercise will take approximately 45 minutes.

**Key Takeaways:**

By the end of this session, the learner will be able to perform static analysis on malware samples, extract useful information, and identify known malware using file hashes.

**Secretary-Style Summary:**

Static malware analysis: extract strings (hardcoded IPs, URLs, commands), analyze file metadata (compiler, original name), calculate hashes (MD5, SHA-1, SHA-256). Use `strings`, `file`, `md5sum` commands. Check VirusTotal for known malware. Document all findings for further investigation. Never execute unknown malware on a production system.

---

**Session 5.2: Dynamic Analysis and Memory Forensics (60 minutes)**

This session teaches the learner how to perform dynamic analysis (executing malware in a safe environment) and analyze memory dumps to identify malicious processes.

**Key Topics Covered:**

Dynamic analysis involves executing malware in an isolated environment (sandbox) and observing its behavior. The learner will understand what to look for: file system modifications, registry changes (on Windows), network connections, and process creation. The session will also introduce memory forensics, which involves analyzing the system's RAM to identify running malware processes, network connections, and injected code.

The learner will be introduced to the Volatility Framework, a powerful tool for analyzing memory dumps. Key Volatility commands include `pslist` (list running processes), `connscan` (find network connections), and `malfind` (identify injected code).

**Practical Walkthrough:**

The learner will be given a memory dump from a system infected with malware. They will use Volatility to analyze the dump, identify malicious processes, find network connections, and identify injected code. This exercise will take approximately 50 minutes and will result in a comprehensive analysis of the malware's runtime behavior.

**Key Takeaways:**

By the end of this session, the learner will be able to perform dynamic analysis in a sandbox environment, use Volatility to analyze memory dumps, and identify malicious processes and network connections.

**Secretary-Style Summary:**

Dynamic analysis: execute malware in sandbox, observe file system changes, registry modifications, network connections, process creation. Memory forensics: use Volatility Framework to analyze RAM dumps. Key commands: `pslist` (processes), `connscan` (network connections), `malfind` (injected code). Identify suspicious processes, network IOCs, and code injection. Document all findings with evidence.

---

**Session 5.3: Reverse Engineering and Malware Family Identification (60 minutes)**

This session teaches the learner the basics of reverse engineering and how to identify malware families.

**Key Topics Covered:**

Reverse engineering involves analyzing the malware's code to understand its functionality. The learner will be introduced to disassemblers like Ghidra (free, open-source) and IDA (commercial but with a free version), which convert binary code into assembly language that can be analyzed.

The learner will also understand the concept of malware families, which are groups of malware that share similar code or functionality. Identifying the malware family helps the SOC analyst understand the attacker's capabilities and predict future attacks. Malware families are identified by analyzing code patterns, strings, and behavior.

**Practical Walkthrough:**

The learner will be given a malware sample and will use Ghidra to disassemble it. They will analyze the code to understand the malware's functionality, identify key functions, and look for patterns that match known malware families. This exercise will take approximately 45 minutes.

**Key Takeaways:**

By the end of this session, the learner will understand the basics of reverse engineering, be able to use a disassembler to analyze malware code, and know how to identify malware families.

**Secretary-Style Summary:**

Reverse engineering: use disassemblers (Ghidra, IDA) to convert binary to assembly code. Analyze code to identify functionality, key functions, and code patterns. Malware families: identified by shared code, strings, and behavior. Compare code patterns with known malware families using resources like MITRE ATT&CK and malware analysis reports. Document findings for threat intelligence.

---

**Session 5.4: Malware Triage Report and Portfolio Project (60 minutes)**

This session teaches the learner how to create a comprehensive malware analysis report suitable for a professional portfolio.

**Key Topics Covered:**

A malware triage report is a concise summary of the malware's characteristics, behavior, and threat level. The report should include the malware's file hash, file type, detected signatures, static analysis findings, dynamic analysis findings, memory forensics findings, and recommended actions. The report should be written in a clear, professional manner suitable for sharing with other SOC analysts or management.

**Practical Walkthrough:**

The learner will be given a malware sample and will perform a complete analysis (static, dynamic, and reverse engineering). They will then create a comprehensive malware analysis report using a provided template. This exercise will take approximately 50 minutes and will result in a LinkedIn-ready portfolio project.

**Key Takeaways:**

By the end of this session, the learner will be able to create a professional malware analysis report that documents all findings and recommendations.

**Secretary-Style Summary:**

Malware analysis report structure: file information (hash, type, size), static analysis findings (strings, metadata), dynamic analysis findings (behavior, network connections), memory forensics findings (processes, injected code), reverse engineering findings (functionality), threat assessment (severity, family), and recommendations (containment, eradication). Write clearly and professionally for SOC team and management.

---

### Module 6: Detection Engineering — Daily Lesson Plan

**Study Duration:** 2 hours per session (recommended: 3 sessions total)

**Session 6.1: Introduction to Detection Engineering and Suricata Rules (60 minutes)**

This session introduces the learner to detection engineering, the process of creating rules to identify malicious activity in network and host logs.

**Key Topics Covered:**

Detection engineering follows a lifecycle: identify (determine what to detect), develop (create detection rules), test (validate rules against known attacks), deploy (implement rules in production), and tune (adjust rules to reduce false positives). The learner will understand this lifecycle and how to apply it to create effective detections.

The session will focus on Suricata, an open-source network intrusion detection and prevention system (IDS/IPS). The learner will learn Suricata rule syntax, including key keywords like `alert`, `flow`, `content`, `pcre` (regular expressions), and `sid` (signature ID). The learner will understand how to write rules that detect specific attack patterns.

**Practical Walkthrough:**

The learner will be given a description of an attack pattern (e.g., "detect HTTP requests to known malicious domains") and will write a Suricata rule to detect it. They will then test the rule against a PCAP file containing both normal and malicious traffic. This exercise will take approximately 45 minutes.

**Key Takeaways:**

By the end of this session, the learner will understand the detection engineering lifecycle, be able to write basic Suricata rules, and know how to test rules against network traffic.

**Secretary-Style Summary:**

Detection engineering lifecycle: Identify (what to detect), Develop (create rules), Test (validate), Deploy (production), Tune (reduce false positives). Suricata rule syntax: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Rule description"; content:"malicious string"; sid:1000001;)`. Key keywords: `flow` (direction), `content` (string matching), `pcre` (regex), `sid` (unique ID). Test rules before deployment.

---

**Session 6.2: YARA Rule Creation and Malware Detection (60 minutes)**

This session teaches the learner how to create YARA rules for detecting malware samples.

**Key Topics Covered:**

YARA is a tool for identifying and classifying malware. YARA rules are written in a simple syntax that allows analysts to describe patterns in malware samples. A YARA rule can match strings, regular expressions, file sizes, and other characteristics. YARA rules are commonly used in malware analysis and incident response to identify known malware.

The learner will learn YARA rule syntax, including how to define strings (literal strings, regular expressions, hexadecimal patterns), conditions (how many strings must match), and metadata (author, date, description). The learner will also understand how to organize YARA rules into rule sets and how to use YARA to scan files or directories.

**Practical Walkthrough:**

The learner will be given a malware sample and will analyze it to identify distinctive strings or patterns. They will then write a YARA rule to detect this malware. They will test the rule by scanning the malware sample and other files to ensure the rule correctly identifies the malware without false positives. This exercise will take approximately 50 minutes.

**Key Takeaways:**

By the end of this session, the learner will be able to create YARA rules for detecting malware, understand how to write effective string patterns, and know how to test rules.

**Secretary-Style Summary:**

YARA rule syntax: `rule malware_name { strings: $a = "malicious_string"; condition: $a; }`. String types: literal strings, regular expressions (`/regex/`), hexadecimal patterns (`{4D 5A}`). Conditions: `all`, `any`, `1 of them`, `2 of them`. Metadata: author, date, description. Test rules by scanning known malware and benign files. Avoid false positives by using specific patterns.

---

**Session 6.3: Sigma Rules and Integration with SIEM (60 minutes)**

This session teaches the learner how to create Sigma rules, which are generic detection rules that can be converted to SIEM-specific queries.

**Key Topics Covered:**

Sigma is a generic signature format for describing detection logic in a SIEM-agnostic way. Sigma rules are written in YAML format and describe what to look for in logs (e.g., Windows Event Logs, syslog, AWS CloudTrail). Sigma rules can be converted to queries for specific SIEM platforms like Splunk, Elasticsearch, or Microsoft Sentinel.

The learner will understand the Sigma rule structure: title, description, logsource (where to look), detection (what to find), and filter (conditions). The learner will also understand how to use Sigma rule converters to generate SIEM-specific queries.

**Practical Walkthrough:**

The learner will be given a description of a detection use case (e.g., "detect failed login attempts followed by successful login from unusual location") and will write a Sigma rule to detect it. They will then use a Sigma rule converter to generate a query for a specific SIEM platform. This exercise will take approximately 50 minutes.

**Key Takeaways:**

By the end of this session, the learner will be able to create Sigma rules, understand how to convert Sigma rules to SIEM queries, and know how to implement detection logic across different platforms.

**Secretary-Style Summary:**

Sigma rule structure: title, description, logsource (Windows Event Log, syslog, CloudTrail), detection (field conditions), filter (AND/OR logic). Example: `EventID: 4625` (failed login), `TargetUserName: admin`. Convert Sigma to SIEM queries using sigma-cli or online converters. Test converted queries in SIEM to ensure correct logic and performance.

---

### Module 7: Live Attack & Defense — Daily Lesson Plan

**Study Duration:** 2 hours per session (recommended: 3 sessions total)

**Session 7.1: Multi-Stage Attack Simulation and Live Triage (90 minutes)**

This session provides a comprehensive, simulated multi-stage attack scenario that the learner will analyze in real-time.

**Key Topics Covered:**

A multi-stage attack typically follows the MITRE ATT&CK framework, which describes tactics and techniques used by adversaries. The learner will understand the typical attack chain: reconnaissance (gathering information), weaponization (preparing tools), delivery (sending malware), exploitation (gaining access), installation (establishing persistence), command and control (communicating with attacker), and actions on objectives (stealing data, disrupting systems).

The session will provide a realistic attack scenario with logs from multiple sources: network traffic (PCAP), host logs (Linux syslog, Windows Event Log), cloud logs (AWS CloudTrail), and email logs. The learner will analyze these logs in real-time to identify the attack stages, the attacker's objectives, and the impact on the organization.

**Practical Walkthrough:**

The learner will be given a scenario: "A user received a phishing email with a malicious attachment. The attachment was executed, and the attacker gained access to the system. The attacker then moved laterally to other systems and exfiltrated sensitive data." The learner will be provided with logs from the initial compromise through the data exfiltration. They will analyze the logs to identify each stage of the attack, document the timeline, and determine the scope of the breach. This exercise will take approximately 90 minutes.

**Key Takeaways:**

By the end of this session, the learner will understand multi-stage attacks, be able to analyze logs from multiple sources to identify attack stages, and know how to determine the scope and impact of a breach.

**Secretary-Style Summary:**

Multi-stage attack chain: Reconnaissance → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives. Analyze logs from multiple sources: PCAP (network), syslog/Event Log (host), CloudTrail (cloud), email logs. Identify each attack stage, document timeline with timestamps, determine scope (systems affected, data accessed). Correlate events across log sources to build complete picture.

---

**Session 7.2: Containment, Eradication, and Incident Reporting (90 minutes)**

This session teaches the learner how to contain an active attack, eradicate the attacker's presence, and create a comprehensive incident report.

**Key Topics Covered:**

Containment involves stopping the attacker's activities and preventing further damage. This may include disconnecting compromised systems from the network, disabling compromised user accounts, or blocking malicious IP addresses at the firewall. Eradication involves removing the attacker's tools and access from the system, such as deleting malware files, removing backdoors, and resetting passwords.

The learner will understand the importance of preserving evidence during containment and eradication. All actions should be documented with timestamps and justifications. The learner will also understand the concept of a "chain of custody," which ensures that evidence is properly handled and can be used in legal proceedings if necessary.

The session will also cover incident reporting, which involves documenting the entire incident from initial detection through resolution. The report should include a timeline of events, analysis of the attack, impact assessment, and recommendations for preventing similar incidents in the future.

**Practical Walkthrough:**

The learner will continue with the multi-stage attack scenario from the previous session. They will now develop a containment strategy, implement eradication steps, and create a comprehensive incident report. The report will include a timeline, analysis, impact assessment, and recommendations. This exercise will take approximately 90 minutes.

**Key Takeaways:**

By the end of this session, the learner will understand containment and eradication strategies, be able to preserve evidence, and know how to create a professional incident report.

**Secretary-Style Summary:**

Containment: disconnect systems, disable accounts, block IPs at firewall. Eradication: delete malware, remove backdoors, reset passwords. Preserve evidence: document all actions with timestamps and justifications. Chain of custody: proper evidence handling for legal proceedings. Incident report: timeline, analysis, impact assessment, recommendations. Follow NIST 800-61 framework. Write clearly for technical and non-technical audiences.

---

**Session 7.3: Capstone Challenge — 10-Minute Incident Summary (90 minutes)**

This session provides a capstone challenge where the learner must rapidly analyze an attack and produce a concise incident summary.

**Key Topics Covered:**

In a real SOC environment, analysts often need to provide rapid updates to management and other teams. The learner will understand how to quickly analyze an incident, extract key information, and communicate findings in a concise, clear manner. This skill is critical for SOC analysts who need to provide updates during an active incident.

The session will teach the learner how to prioritize information, focus on the most critical findings, and present information in a way that is useful to different audiences (technical analysts, management, executives).

**Practical Walkthrough:**

The learner will be given a new attack scenario with logs from multiple sources. They will have 10 minutes to analyze the logs, identify key findings, and produce a one-page incident summary suitable for management. The summary should include: incident title, timeline of key events, systems affected, data at risk, and recommended immediate actions. This exercise will take approximately 90 minutes (including analysis and writing).

**Key Takeaways:**

By the end of this session, the learner will be able to rapidly analyze an incident, prioritize findings, and communicate effectively with different audiences.

**Secretary-Style Summary:**

Rapid incident analysis: focus on critical findings, identify systems affected, determine data at risk, recommend immediate actions. One-page incident summary: title, timeline (key events only), affected systems, data impact, immediate actions. Write for management: avoid technical jargon, focus on business impact. Practice rapid analysis to improve speed and accuracy.

---

### Module 8: SOC Interview Simulation — Daily Lesson Plan

**Study Duration:** 2 hours per session (recommended: 2 sessions total)

**Session 8.1: Technical Mock Interview and Whiteboard Scenarios (90 minutes)**

This session provides a comprehensive technical mock interview to prepare the learner for real SOC job interviews.

**Key Topics Covered:**

The session will include 30 technical questions covering incident response, network analysis, cloud security, and detection engineering. The questions will range from basic (e.g., "What is the difference between a virus and a worm?") to advanced (e.g., "How would you design a detection rule for a zero-day exploit?").

The session will also include whiteboard-style scenarios where the learner must verbally walk through an incident response process or explain a technical concept. These scenarios simulate real interview situations where candidates are asked to explain their thinking process.

**Practical Walkthrough:**

The learner will be given 30 technical questions and will answer them in writing or verbally (if possible, with a mentor or peer). They will also be given 3 whiteboard scenarios and will walk through their approach to solving each scenario. This exercise will take approximately 90 minutes.

**Key Takeaways:**

By the end of this session, the learner will have practiced answering technical interview questions, be familiar with common interview scenarios, and know how to explain their thinking process clearly.

**Secretary-Style Summary:**

Technical interview preparation: study 30 common SOC questions (IR process, network analysis, cloud security, detection). Practice whiteboard scenarios: walk through incident response process, explain detection logic, analyze attack chains. Prepare clear, concise answers. Practice explaining technical concepts to non-technical audiences. Record yourself to identify areas for improvement.

---

**Session 8.2: Behavioral Interview Prep and Career Roadmap (90 minutes)**

This session teaches the learner how to prepare for behavioral interview questions and develop a long-term career roadmap.

**Key Topics Covered:**

Behavioral interview questions ask about past experiences and how the learner handled specific situations. These questions are designed to assess soft skills like teamwork, communication, and problem-solving. The learner will understand the STAR method (Situation, Task, Action, Result), which is a structured way to answer behavioral questions.

The session will also cover career development, including the progression from SOC Tier 1 to Tier 2 to specialized roles like Cloud Security Analyst or Threat Hunter. The learner will develop a personalized career roadmap that includes skill development goals, certifications to pursue, and timeline for career progression.

**Practical Walkthrough:**

The learner will be given 10 common behavioral questions and will prepare STAR-method answers. They will also develop a personalized career roadmap for the next 6 months, 1 year, and 3 years. This exercise will take approximately 90 minutes.

**Key Takeaways:**

By the end of this session, the learner will be able to answer behavioral questions effectively, understand their career progression options, and have a concrete plan for achieving their career goals.

**Secretary-Style Summary:**

Behavioral interview: use STAR method (Situation, Task, Action, Result). Prepare answers for common questions: "Tell me about a time you handled a difficult situation," "How do you work in a team?" Career roadmap: SOC Tier 1 (current) → Tier 2 (1 year) → Specialist (Cloud/Threat Hunting, 2-3 years). Develop skills: Linux, AWS, detection engineering, threat hunting. Pursue certifications: Security+, CEH, GIAC. Build portfolio with projects.

---

## 90-Day Study Schedule (Optimized for 10-Hour Workdays)

The following schedule is designed for a learner who works 10-hour shifts and can study 1-2 hours per night.

| Week | Module | Session | Topic | Study Time | Hands-On Labs |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | 1 | 1.1 | Phishing Fundamentals | 1 hour | Email Header Analysis Lab |
| 1 | 1 | 1.2 | OSINT for Threat Enrichment | 1 hour | Domain Investigation Lab |
| 2 | 1 | 1.3 | PCAP Analysis & Ticketing | 1 hour | PCAP Analysis Lab, Ticket Creation |
| 2 | 2 | 2.1 | IAM Abuse & Privilege Escalation | 1 hour | Host Log Analysis Lab |
| 3 | 2 | 2.2 | Host Log Analysis & Timeline | 1 hour | User Activity Timeline Lab |
| 3 | 2 | 2.3 | Cloud IAM Investigation | 1 hour | CloudTrail Analysis Lab |
| 4 | 3 | 3.1 | Data Exfiltration Patterns | 1 hour | Network Traffic Analysis Lab |
| 4 | 3 | 3.2 | File Transfer Protocol Analysis | 1 hour | FTP/SFTP Analysis Lab |
| 5 | 3 | 3.3 | Linux Disk Forensics | 1 hour | SleuthKit Lab |
| 5 | 4 | 4.1 | DDoS Attack Types & Detection | 1 hour | DDoS Traffic Analysis Lab |
| 6 | 4 | 4.2 | DDoS Mitigation & Cloud Defenses | 1 hour | AWS Shield/WAF Configuration Lab |
| 6 | 5 | 5.1 | Malware Triage & Static Analysis | 1 hour | Static Analysis Lab |
| 7 | 5 | 5.2 | Dynamic Analysis & Memory Forensics | 1 hour | Volatility Framework Lab |
| 7 | 5 | 5.3 | Reverse Engineering & Malware Families | 1 hour | Ghidra Disassembly Lab |
| 8 | 5 | 5.4 | Malware Analysis Report | 1 hour | Portfolio Project: Malware Report |
| 8 | 6 | 6.1 | Suricata Rule Creation | 1 hour | Suricata Rule Lab |
| 9 | 6 | 6.2 | YARA Rule Creation | 1 hour | YARA Rule Lab |
| 9 | 6 | 6.3 | Sigma Rules & SIEM Integration | 1 hour | Sigma Rule Lab |
| 10 | 7 | 7.1 | Multi-Stage Attack Simulation | 1.5 hours | Live Attack Analysis Lab |
| 10 | 7 | 7.2 | Containment & Incident Reporting | 1.5 hours | Incident Report Project |
| 11 | 7 | 7.3 | Capstone Challenge | 1.5 hours | 10-Minute Incident Summary |
| 11 | 8 | 8.1 | Technical Mock Interview | 1.5 hours | Mock Interview Practice |
| 12 | 8 | 8.2 | Behavioral Interview & Career Roadmap | 1.5 hours | Career Planning |

**Total Study Time:** Approximately 30-35 hours over 12 weeks (2.5-3 hours per week, or 20-30 minutes per night)

**Recommended Study Schedule:**

- **Monday-Thursday:** 1 hour study session (theory + hands-on lab)
- **Friday:** 1-1.5 hour study session (review + portfolio project work)
- **Weekend:** Optional review or additional lab practice

This schedule allows for flexibility and accommodates the learner's 10-hour workday schedule.

---

## 6-Month SOC Career Roadmap (Tier 1 → Tier 2 → Specialist)

The following roadmap outlines the learner's progression from SOC Analyst I to specialized roles over 6 months.

**Months 1-2: SOC Analyst I (Foundation)**

During the first two months, the learner will complete this course and focus on mastering Tier 1 skills: phishing triage, basic malware analysis, and incident ticket creation. The learner will work on building a portfolio of 8-10 projects demonstrating these skills.

**Months 3-4: SOC Analyst I (Advanced) → Tier 2 Preparation**

During months 3-4, the learner will deepen their skills in detection engineering, threat hunting, and cloud security. They will begin studying for advanced certifications (Security+, CEH) and will start contributing to detection rule development in their organization.

**Months 5-6: SOC Analyst II / Specialist Role**

By months 5-6, the learner will be ready to transition to a Tier 2 role or a specialized role such as Cloud Security Analyst or Threat Hunter. The learner should have completed advanced certifications and have a strong portfolio demonstrating expertise in their chosen specialization.

**Key Certifications to Pursue:**

- **Month 1-2:** CompTIA Security+ (foundational)
- **Month 3-4:** Certified Ethical Hacker (CEH) or GIAC Security Essentials (GSEC)
- **Month 5-6:** AWS Certified Security Specialist or GIAC Certified Incident Handler (GCIH)

**Skills to Develop:**

- **Months 1-2:** Phishing triage, malware analysis, incident response, ticketing
- **Months 3-4:** Detection engineering, threat hunting, cloud security (AWS), Linux forensics
- **Months 5-6:** Advanced threat hunting, cloud architecture, security automation, AI-augmented SOC workflows

**Portfolio Projects to Complete:**

- **Months 1-2:** Phishing playbook, malware analysis reports, incident response reports (8-10 projects)
- **Months 3-4:** Detection rule packs, threat hunting reports, cloud security assessments (5-7 projects)
- **Months 5-6:** Advanced incident reports, security automation scripts, cloud security architecture designs (3-5 projects)

---



---

## Slide Deck Generator Version: Slide-Ready Content

This section provides the core content, structured as slide-ready bullet points, for every lesson in the course. Each section also includes a description of the essential visual assets (diagrams, workflows, cheat sheets) required for the slide deck.

### Module 1: Phishing Attack

#### Session 1.1: Phishing Fundamentals and Email Header Analysis

**Slide Content:**

*   **Phishing: The #1 SOC Threat:** The primary initial access vector, often targeting credentials or delivering malware.
*   **Phishing Kill Chain:** Reconnaissance → Weaponization → Delivery → Exploitation → Post-Compromise.
*   **Email Header Analysis:** Metadata is the key to truth. Focus on `Received`, `Return-Path`, and `X-Originating-IP`.
*   **Authentication Checks:** Verify SPF, DKIM, and DMARC results to detect domain spoofing.
*   **Triage Goal:** Rapidly identify malicious intent and contain the threat before user interaction.

**Visual Assets:**

*   **Diagram:** **Phishing Kill Chain** (Simple 5-step flow chart).
*   **Cheat Sheet:** **Email Header Field Guide** (Table mapping key fields to their investigative purpose).
*   **Workflow:** **Phishing Triage Workflow** (Flowchart: User Report → Header Analysis → OSINT → Containment).

#### Session 1.2: OSINT for Threat Enrichment

**Slide Content:**

*   **Threat Enrichment:** Adding context (reputation, history, ownership) to IOCs (IPs, domains, hashes).
*   **VirusTotal:** The go-to for file hash and domain reputation checks. Look for multiple engine hits.
*   **Whois & Shodan:** Identify domain ownership and exposed services on the attacker's infrastructure.
*   **AbuseIPDB:** Check for historical abuse reports against the source IP address.
*   **OSINT Best Practice:** Use multiple sources for cross-validation; document all findings in the ticket.

**Visual Assets:**

*   **Diagram:** **OSINT Tool Ecosystem** (Hub-and-spoke diagram with IOC in the center and tools around it).
*   **Cheat Sheet:** **OSINT Quick Reference Table** (Tool, Purpose, Key Data Point).
*   **Workflow:** **IOC Enrichment Process** (Flowchart showing the sequence of checking an IP/Domain/Hash).

#### Session 1.3: PCAP Analysis and Ticketing Simulation

**Slide Content:**

*   **Post-Compromise Network Activity:** Look for C2 beaconing, data exfiltration, or secondary malware downloads.
*   **Wireshark Filters:** Essential for isolating traffic (e.g., `http.request`, `dns`, `ip.addr == X.X.X.X`).
*   **NIST 800-61 Framework:** The standard for IR: Preparation, Detection & Analysis, Containment, Eradication & Recovery, Post-Incident Activity.
*   **Ticket Creation:** Document the **Who, What, When, Where, Why, and How** of the incident.
*   **Key Deliverable:** A clear, concise summary of the incident scope and recommended next steps.

**Visual Assets:**

*   **Diagram:** **NIST 800-61 Incident Response Lifecycle** (Circular or linear flow diagram).
*   **Cheat Sheet:** **Essential Wireshark Filters** (List of 5-7 high-value filters for SOC analysis).
*   **Template:** **Incident Ticket Structure** (Outline of required fields: Summary, IOCs, Timeline, Actions Taken).

### Module 2: Unauthorized Access

#### Session 2.1: IAM Abuse and Privilege Escalation

**Slide Content:**

*   **Unauthorized Access Vectors:** Credential theft, weak passwords, insider threat, misconfiguration.
*   **Privilege Escalation:** Moving from a low-privilege user to a higher-privilege user (e.g., `root`, `Administrator`).
*   **Linux Indicators:** Sudo abuse, changes to `/etc/passwd` or `/etc/shadow`, unusual process execution.
*   **AWS IAM Abuse:** Creation of unauthorized access keys, policy modification (`AttachUserPolicy`), or role assumption.
*   **Detection Focus:** Look for a spike in failed login attempts followed by a successful login from a new location.

**Visual Assets:**

*   **Diagram:** **Privilege Escalation Attack Chain** (Flowchart showing initial access to root/admin).
*   **Cheat Sheet:** **Linux Auth Log Indicators** (Table of key log entries and their meaning).
*   **Workflow:** **IAM Incident Triage** (Flowchart: Alert → Check CloudTrail → Suspend User → Revoke Keys).

#### Session 2.2: Host Log Analysis and User Activity Timeline

**Slide Content:**

*   **Host Logs are the Truth:** They provide the most granular view of attacker actions on a system.
*   **Linux Log Sources:** `/var/log/auth.log` (authentication), `journalctl` (systemd events).
*   **Windows Log Sources:** Security Event Log (Event IDs 4624/4625 for login/logout).
*   **Timeline Creation:** The process of ordering all log events chronologically to reconstruct the attack.
*   **Forensic Tools:** Use `grep`, `awk`, and `sed` for efficient log parsing on the command line.

**Visual Assets:**

*   **Diagram:** **Host Log Analysis Process** (Steps: Collect → Filter → Parse → Timeline → Analyze).
*   **Cheat Sheet:** **Essential Linux Log Commands** (List of `grep`, `awk`, ` and `sed` examples for log filtering).
*   **Template:** **User Activity Timeline Format** (Table with columns: Timestamp, Source, Event, Description).

#### Session 2.3: Cloud IAM Investigation and Lateral Movement Detection

**Slide Content:**

*   **CloudTrail:** The definitive source for all AWS API calls—who did what, when, and where.
*   **GuardDuty Alerts:** High-value, pre-analyzed alerts for suspicious cloud activity (e.g., API calls from Tor).
*   **Lateral Movement:** Attacker moving from the initial compromised host to other systems (e.g., via SSH, RDP).
*   **VPC Flow Logs:** Network traffic records between AWS resources—essential for detecting internal lateral movement.
*   **Containment:** Suspend compromised IAM users/roles and revoke all associated access keys immediately.

**Visual Assets:**

*   **Diagram:** **CloudTrail Log Flow** (Diagram showing API calls → CloudTrail → S3/SIEM).
*   **Cheat Sheet:** **Key CloudTrail Event Names** (Table of events like `CreateAccessKey`, `RunInstances`, `AttachUserPolicy`).
*   **Workflow:** **Lateral Movement Detection** (Flowchart: Alert on Host A → Check VPC Flow Logs for connections to Host B/C → Investigate Host B/C).

### Module 3: Data Loss / Exfiltration

#### Session 3.1: Data Exfiltration Patterns and Detection

**Slide Content:**

*   **Exfiltration Channels:** HTTP/HTTPS, DNS Tunneling, Email, Cloud Storage APIs, and ICMP.
*   **Detection Indicators:** Large file transfers, unusual data volume spikes, or connections to suspicious external hosts.
*   **DNS Tunneling:** Using DNS queries to sneak data out; look for unusually long or frequent DNS requests.
*   **Beaconing:** Small, regular network connections to a C2 server, often disguised as normal traffic.
*   **DLP Strategy:** Identify sensitive data, monitor access, and block unauthorized transfers.

**Visual Assets:**

*   **Diagram:** **Data Exfiltration Techniques Map** (Mind map of techniques categorized by protocol).
*   **Cheat Sheet:** **Exfil Indicators Checklist** (List of network and host-based signs of data loss).
*   **Workflow:** **Data Loss Incident Triage** (Flowchart: Alert → Confirm Data Type → Identify Channel → Containment).

#### Session 3.2: File Transfer Protocol Analysis and Cloud Data Forensics

**Slide Content:**

*   **PCAP Analysis for Exfil:** Filter for FTP, SFTP, and large HTTP POST requests.
*   **Cloud Data Forensics:** S3 Access Logs and CloudTrail are the primary evidence sources.
*   **S3 Access Indicators:** Excessive `GetObject` or `ListBucket` calls from a single source.
*   **Insider Threat:** Look for data access patterns that deviate from a user's normal behavior.
*   **Containment Action:** Block the external IP, disable the compromised account, and revoke S3 permissions.

**Visual Assets:**

*   **Diagram:** **Cloud Data Exfil Chain** (Diagram showing compromised EC2 → S3 Bucket → External IP).
*   **Cheat Sheet:** **S3 Access Log Fields** (Table of key fields: `Operation`, `Key`, `Requester`, `RemoteIP`).
*   **Workflow:** **Cloud Exfil Investigation** (Steps: CloudTrail/S3 Logs → Identify Source/Destination → Scope Impact → Contain).

#### Session 3.3: Linux Disk Forensics and Data Loss Prevention

**Slide Content:**

*   **Disk Forensics Goal:** Recover deleted files, analyze file system metadata, and reconstruct file access history.
*   **Linux Tools:** SleuthKit (`fls`, `icat`, `istat`) and Autopsy (GUI front-end).
*   **Key Metadata:** **MACE** (Modified, Accessed, Created, Entry Modified) timestamps.
*   **Data Preservation:** Create a forensic image (copy) of the disk before any analysis or remediation.
*   **DLP Implementation:** Use file integrity monitoring (FIM) and data classification to protect critical assets.

**Visual Assets:**

*   **Diagram:** **Forensic Imaging Process** (Simple diagram: Disk → Write Blocker → Forensic Image).
*   **Cheat Sheet:** **SleuthKit Command Reference** (List of 5 essential commands and their function).
*   **Process Map:** **Evidence Handling Chain of Custody** (Flowchart showing proper documentation steps).

### Module 4: DDoS Attack

#### Session 4.1: DDoS Attack Types and Detection

**Slide Content:**

*   **DDoS Objective:** Deny service availability by overwhelming resources (bandwidth, CPU, application).
*   **Layer 3/4 Attacks:** Volumetric attacks (UDP/ICMP floods, SYN floods) targeting network infrastructure.
*   **Layer 7 Attacks:** Application-layer attacks (HTTP floods) targeting web server resources.
*   **Detection:** Look for massive spikes in traffic volume, high connection rates, and unusual source IP diversity.
*   **Botnets:** Networks of compromised machines used to launch coordinated, large-scale attacks.

**Visual Assets:**

*   **Diagram:** **DDoS Attack Taxonomy** (Tree diagram classifying attacks by Layer 3/4 and Layer 7).
*   **Cheat Sheet:** **DDoS Indicators Checklist** (List of signs in NetFlow/PCAP: volume, rate, packet size).
*   **Threat Chain:** **Botnet Attack Chain** (Diagram: Attacker → C2 Server → Botnet → Target).

#### Session 4.2: DDoS Mitigation and Cloud-Based Defenses

**Slide Content:**

*   **Mitigation Strategies:** Rate Limiting, Traffic Filtering (ACLs), and Traffic Scrubbing (DDoS protection services).
*   **Cloud-Native Defense:** AWS Shield (always-on protection), WAF (Layer 7 filtering), CloudFront (caching/distribution).
*   **Rate-Based Rules:** WAF rules that automatically block IPs exceeding a defined request threshold.
*   **Triage Goal:** Differentiate legitimate traffic spikes from malicious traffic to avoid over-blocking.
*   **Post-Incident:** Analyze attack vectors to harden defenses and tune rate-limiting thresholds.

**Visual Assets:**

*   **Diagram:** **Cloud DDoS Mitigation Architecture** (Diagram showing traffic flow through CloudFront, WAF, and Shield before reaching the application).
*   **Cheat Sheet:** **DDoS Mitigation Steps** (Checklist for immediate response: Verify, Notify, Mitigate, Monitor).
*   **Workflow:** **DDoS Triage Workflow** (Flowchart: Alert → Identify Type → Apply Mitigation → Monitor Effectiveness).

### Module 5: Malware Attack

#### Session 5.1: Malware Triage and Static Analysis

**Slide Content:**

*   **Malware Types:** Viruses, Worms, Trojans, Ransomware, Spyware.
*   **Static Analysis:** Examining the file without execution. Safe, fast, and provides initial IOCs.
*   **Key Static Data:** File hash (reputation check), Strings (IPs, URLs, API calls), File Metadata (compiler, timestamps).
*   **Tools:** `strings`, `file`, `md5sum`/`sha256sum`, VirusTotal.
*   **Triage Goal:** Determine if the file is malicious and gather initial intelligence for dynamic analysis.

**Visual Assets:**

*   **Diagram:** **Malware Triage Flow** (Flowchart: Submission → Static Analysis → Dynamic Analysis → Reporting).
*   **Cheat Sheet:** **Static Analysis Command Reference** (List of essential command-line tools and their output).
*   **Template:** **Malware Triage Checklist** (List of data points to collect during static analysis).

#### Session 5.2: Dynamic Analysis and Memory Forensics

**Slide Content:**

*   **Dynamic Analysis:** Executing the malware in a controlled, isolated environment (sandbox).
*   **Behavioral Indicators:** File system changes, registry modifications, process injection, network connections.
*   **Memory Forensics:** Analyzing RAM to find evidence that is volatile and not on the disk.
*   **Volatility Framework:** The industry standard for memory analysis.
*   **Key Volatility Commands:** `pslist` (processes), `connscan` (network connections), `malfind` (injected code).

**Visual Assets:**

*   **Diagram:** **Dynamic Analysis Sandbox Architecture** (Diagram showing malware execution in a VM with monitoring tools).
*   **Cheat Sheet:** **Volatility Command Quick Guide** (Table of commands and what they reveal).
*   **Process Map:** **Memory Acquisition Steps** (Steps for safely acquiring a memory dump).

#### Session 5.3: Reverse Engineering and Malware Family Identification

**Slide Content:**

*   **Reverse Engineering (Basics):** Analyzing the binary code to understand its function and intent.
*   **Disassemblers:** Tools like Ghidra (free) and IDA Pro (commercial) convert machine code to assembly.
*   **Malware Families:** Groups of malware sharing code, TTPs, or C2 infrastructure (e.g., Emotet, TrickBot).
*   **Identification Value:** Knowing the family predicts behavior and informs defense strategy.
*   **MITRE ATT&CK:** Map observed malware behavior to known adversary tactics and techniques.

**Visual Assets:**

*   **Diagram:** **Reverse Engineering Workflow** (Flowchart: Binary → Disassembler → Assembly Code → Analysis).
*   **Cheat Sheet:** **Common Malware Family Indicators** (Table of 3-4 major families and their unique characteristics).
*   **Threat Chain:** **Malware Execution Chain** (Diagram: Initial Dropper → Loader → Payload → C2).

#### Session 5.4: Malware Triage Report and Portfolio Project

**Slide Content:**

*   **Report Purpose:** Communicate technical findings to both technical teams and management.
*   **Report Structure:** Executive Summary, Incident Details, Static Analysis, Dynamic Analysis, Conclusion, Recommendations.
*   **Key Metrics:** File hash, C2 IP/Domain, MITRE ATT&CK mapping, Severity Score.
*   **Portfolio Project:** A high-quality, professional report demonstrates end-to-end analysis capability.
*   **Recommendation Focus:** Containment (immediate), Eradication (long-term), and Prevention (hardening).

**Visual Assets:**

*   **Template:** **Malware Analysis Report Outline** (Detailed structure of the final report).
*   **Example:** **Executive Summary Example** (A concise, non-technical summary for a manager).
*   **Table:** **IOC Summary Table** (Table of all collected IOCs: Type, Value, Source, Status).

### Module 6: Detection Engineering

#### Session 6.1: Introduction to Detection Engineering and Suricata Rules

**Slide Content:**

*   **Detection Engineering Lifecycle:** Identify → Develop → Test → Deploy → Tune.
*   **Goal:** Shift from reactive incident response to proactive threat detection.
*   **Suricata:** Open-source Network IDS/IPS. Uses rules to inspect network traffic.
*   **Rule Structure:** `Action Protocol Source_IP Source_Port -> Dest_IP Dest_Port (Rule Options)`.
*   **Rule Options:** `msg` (alert message), `content` (string match), `sid` (signature ID).

**Visual Assets:**

*   **Diagram:** **Detection Engineering Lifecycle** (Circular diagram showing the 5 stages).
*   **Cheat Sheet:** **Suricata Rule Syntax** (Breakdown of the rule structure with examples).
*   **Workflow:** **Rule Development Process** (Flowchart: Threat Intel → Write Rule → Test with PCAP → Deploy).

#### Session 6.2: YARA Rule Creation and Malware Detection

**Slide Content:**

*   **YARA Purpose:** The "Pattern Matching Swiss Knife" for identifying and classifying malware files.
*   **Rule Components:** `meta` (metadata), `strings` (patterns to look for), `condition` (logic for matching).
*   **String Types:** Text strings, hexadecimal patterns, and regular expressions.
*   **Condition Logic:** Define how many strings must match (e.g., `all of them`, `1 of ($a, $b)`, `filesize > 1MB`).
*   **Best Practice:** Write rules that are specific enough to avoid false positives but generic enough to catch variants.

**Visual Assets:**

*   **Diagram:** **YARA Rule Structure** (Visual breakdown of a rule with its three main sections).
*   **Cheat Sheet:** **YARA Condition Examples** (Table of common condition statements).
*   **Example:** **Simple YARA Rule** (A fully annotated example rule).

#### Session 6.3: Sigma Rules and Integration with SIEM

**Slide Content:**

*   **Sigma:** The generic signature format for log events. "The YAML for SIEM."
*   **SIEM Agnostic:** Write once, convert to many (Splunk, Elastic, Sentinel, etc.).
*   **Rule Structure:** `logsource` (where to look), `detection` (the logic), `title/description`.
*   **Conversion:** Use the Sigma CLI tool to translate YAML into native SIEM queries.
*   **Use Case:** Ideal for detecting host-based TTPs (e.g., PowerShell execution, service creation).

**Visual Assets:**

*   **Diagram:** **Sigma Conversion Flow** (Diagram: Sigma YAML → Converter → SIEM Query).
*   **Cheat Sheet:** **Sigma Logsource Types** (Table of common log sources: `windows`, `linux`, `cloudtrail`).
*   **Example:** **Basic Sigma Rule YAML** (Annotated YAML snippet).

### Module 7: Live Attack & Defense

#### Session 7.1: Multi-Stage Attack Simulation and Live Triage

**Slide Content:**

*   **Multi-Stage Attack:** A sequence of TTPs designed to achieve a complex objective (e.g., APT).
*   **MITRE ATT&CK:** The framework for mapping and understanding adversary behavior.
*   **Live Triage:** Rapidly analyzing incoming alerts and logs to understand the attack's current phase.
*   **Log Correlation:** The most challenging part—connecting events across different systems (host, network, cloud).
*   **Goal:** Identify the **Initial Access** point and the **Action on Objectives** (the goal).

**Visual Assets:**

*   **Diagram:** **Multi-Stage Attack Chain (MITRE Mapping)** (Flowchart showing TTPs mapped to MITRE stages).
*   **Cheat Sheet:** **Log Correlation Checklist** (List of data points to match: IP, User, Timestamp, Process ID).
*   **Threat Chain:** **Example Attack Scenario** (Phishing → PowerShell → C2 → Data Exfil).

#### Session 7.2: Containment, Eradication, and Incident Reporting

**Slide Content:**

*   **Containment:** Stop the bleeding. Isolate the host, disable the account, block the C2 IP.
*   **Eradication:** Remove the root cause and all persistence mechanisms (malware, backdoors, rogue accounts).
*   **Recovery:** Restore systems to normal operation (patching, rebuilding, restoring data).
*   **Evidence Preservation:** Maintain the **Chain of Custody** for all collected artifacts.
*   **Incident Report:** The final record. Must be accurate, detailed, and include lessons learned.

**Visual Assets:**

*   **Diagram:** **Containment Strategies** (Table of techniques: Network Isolation, Account Suspension, Firewall Block).
*   **Cheat Sheet:** **NIST IR Steps (C-E-R)** (Checklist for Containment, Eradication, and Recovery).
*   **Template:** **Incident Report Section Outline** (Summary, Findings, Impact, Recommendations).

#### Session 7.3: Capstone Challenge — 10-Minute Incident Summary

**Slide Content:**

*   **Rapid Reporting:** Essential for executive communication during a crisis.
*   **Focus:** Business impact, scope, and immediate actions—not technical minutiae.
*   **Key Elements:** Incident Title, Current Status, Affected Systems, Data Impact, Next Steps.
*   **The "Secretary Summary":** Concise, dense, and actionable information for decision-makers.
*   **Challenge Goal:** Practice synthesizing complex data into a clear, one-page brief under pressure.

**Visual Assets:**

*   **Template:** **Executive Incident Briefing Template** (One-page layout with clear sections).
*   **Example:** **Bad vs. Good Summary** (Side-by-side comparison of a poor vs. effective executive summary).
*   **Process Map:** **Rapid Analysis Workflow** (Steps for quickly prioritizing log data).

### Module 8: SOC Interview Simulation

#### Session 8.1: Technical Mock Interview and Whiteboard Scenarios

**Slide Content:**

*   **Technical Interview Prep:** Master the fundamentals of IR, networking, Linux, and cloud security.
*   **Whiteboard Scenarios:** Demonstrate your thought process, not just the final answer.
*   **Scenario Walkthrough:** Start with **Detection**, move to **Containment**, then **Eradication**, and finally **Reporting**.
*   **Key Areas:** OSI Model, TCP/IP, Common Ports, Malware Types, Cloud Services (S3, EC2, IAM).
*   **Confidence:** Practice articulating complex ideas clearly and concisely.

**Visual Assets:**

*   **Cheat Sheet:** **30 Technical Interview Questions** (List of questions categorized by topic).
*   **Diagram:** **IR Whiteboard Walkthrough** (Visual representation of the C-E-R process).
*   **Table:** **Common Port/Protocol Reference** (Table of 10 key ports and their use).

#### Session 8.2: Behavioral Interview Prep and Career Roadmap

**Slide Content:**

*   **Behavioral Questions:** Assess soft skills, teamwork, and problem-solving under pressure.
*   **The STAR Method:** **S**ituation, **T**ask, **A**ction, **R**esult—the structured way to answer.
*   **Resume Optimization:** Highlight quantifiable achievements and portfolio projects.
*   **Career Roadmap:** Tier 1 → Tier 2 → Specialist (Cloud/Threat Hunting). Have a 6-month plan.
*   **Next Steps:** Focus on certifications (Security+, AWS Security) and continuous learning (Linux scripting).

**Visual Assets:**

*   **Diagram:** **STAR Method Breakdown** (Visual guide to the four components).
*   **Cheat Sheet:** **10 Behavioral Interview Questions** (List of common questions).
*   **Table:** **6-Month Career Roadmap** (Timeline with Milestones: Certifications, Projects, Role Transition).

---


---

## Video Script Generator Version: Module 1 (Phishing Attack)

This section provides the full video script for Module 1, structured with narration, scene descriptions, and visual explanations, as required for a visual learner.

### Video 1.1: Phishing Fundamentals and Email Header Analysis

| Time | Speaker | Narration Script | Scene/Visual Description |
| :--- | :--- | :--- | :--- |
| **0:00** | **[INTRO MUSIC/TITLE CARD]** | | **TITLE CARD:** SOC Analyst I — From Cradle to Grave. **MODULE 1:** Phishing Attack. **LESSON 1.1:** Phishing Fundamentals and Email Header Analysis. |
| **0:15** | **[NARRATOR]** | Welcome to the front lines of the Security Operations Center. If you work in a SOC, your first and most frequent enemy will be the **Phishing Attack**. It is the number one initial access vector, and your ability to triage it quickly is your most valuable skill. | **VISUAL:** Animated graphic showing a simplified **Phishing Kill Chain** (Email Delivery → User Click → Malware/Credential Theft → C2). |
| **0:45** | **[NARRATOR]** | Phishing is a social engineering attack. It's designed to trick a user into revealing sensitive information or executing malicious code. Think of it as a digital fishing expedition. The attacker casts a wide net, hoping someone takes the bait. | **VISUAL:** Split screen. Left: A convincing, but fake, email from "IT Support." Right: A diagram of the **Phishing Kill Chain** with the "Delivery" and "Exploitation" stages highlighted. |
| **1:15** | **[NARRATOR]** | Our job as SOC Analysts is to stop the attack before it becomes a breach. Our first piece of evidence is the email itself. But the email you see in your inbox is a lie. The truth is hidden in the **Email Header**. | **VISUAL:** Zoom in on a sample email. A red box highlights the "From" address, which looks legitimate. Transition to a screen showing the raw email header text. |
| **1:45** | **[NARRATOR]** | The header is a log of every server the email passed through. We focus on three key areas. First, the **Received** lines. These show the path the email took. We read them from bottom to top to trace the origin. Second, the **Return-Path** and **X-Originating-IP**. This is often the true source IP of the sender. | **DEMO:** Screen recording of an analyst in a text editor. They highlight a `Received` line and an `X-Originating-IP`. Use callouts to explain what each field means. |
| **2:30** | **[NARRATOR]** | Finally, we check the authentication headers: **SPF, DKIM, and DMARC**. If an email claims to be from `amazon.com` but the SPF check fails, we know it's a spoof. A failed check is a massive red flag. | **VISUAL:** Animated graphic of a green checkmark for a successful SPF/DKIM/DMARC check, followed by a red X for a failed check. |
| **3:00** | **[NARRATOR]** | **LAB WALKTHROUGH:** Let's put this into practice. We have a suspicious email. I'll show you step-by-step how to extract the raw header from a common email client and then analyze it. We'll use a simple online tool to paste the header and trace the path. | **DEMO:** Guided walkthrough of extracting a header and pasting it into a header analyzer tool. The analyst points out the spoofed domain and the true originating IP. |
| **4:00** | **[NARRATOR]** | **Secretary-Style Summary:** Phishing is the primary entry point. Email headers contain the truth about the sender and path. Read `Received` lines bottom-up. Verify the `X-Originating-IP`. Always check SPF, DKIM, and DMARC. Preserve the raw header as evidence. | **VISUAL:** A clean, concise **Secretary-Style Summary** text box appears on screen, summarizing the key points. |
| **4:30** | **[NARRATOR]** | Your first lab is to analyze three sample headers provided in the course materials. In our next video, we'll take the IOCs we find and use **OSINT** to enrich our investigation. | **VISUAL:** End screen with a call to action for the lab and a preview of the next video's topic. |

### Video 1.2: OSINT for Threat Enrichment

| Time | Speaker | Narration Script | Scene/Visual Description |
| :--- | :--- | :--- | :--- |
| **0:00** | **[NARRATOR]** | We've analyzed the header and found an Indicator of Compromise, let's say a suspicious IP address. Now, we need to add context. This is where **OSINT**, or Open-Source Intelligence, comes in. | **VISUAL:** Diagram of the **IOC Enrichment Process** with the suspicious IP in the center. |
| **0:30** | **[NARRATOR]** | **VirusTotal** is our first stop. We can check the reputation of file hashes, domains, and IP addresses. If 50 different security vendors have flagged this IP as malicious, we know we have a high-confidence threat. | **DEMO:** Analyst navigates to VirusTotal, pastes the suspicious IP, and shows the results, pointing out the "Detection Ratio." |
| **1:15** | **[NARRATOR]** | Next, **Whois** and **Shodan**. Whois tells us who registered the domain and when. A newly registered domain with privacy protection is a classic phishing sign. Shodan is the "search engine for the Internet of Things." We use it to see what services are running on the attacker's IP. | **DEMO:** Analyst uses a Whois lookup tool, highlighting the creation date. Then, they use Shodan to search the IP, showing open ports or services. |
| **2:00** | **[NARRATOR]** | **AbuseIPDB** is another critical tool. It aggregates reports of malicious activity. If our IP has been reported for brute-forcing or spamming, it confirms our suspicion. The key is to cross-validate. Never rely on a single source. | **DEMO:** Analyst checks the IP on AbuseIPDB, showing the "Confidence Score" and historical reports. |
| **2:45** | **[NARRATOR]** | **LAB WALKTHROUGH:** We'll take the IP address we found in the last video and run a full OSINT investigation. We'll document the creation date, the hosting provider, and the reputation score. This documentation is what goes into your final incident report. | **DEMO:** Guided walkthrough, documenting findings in a simple Markdown table as they go. |
| **3:45** | **[NARRATOR]** | **Secretary-Style Summary:** OSINT adds context to IOCs. Use VirusTotal for reputation, Whois for domain age, Shodan for services, and AbuseIPDB for historical reports. Cross-validate all findings. Document everything. | **VISUAL:** A clean, concise **Secretary-Style Summary** text box appears on screen. |
| **4:15** | **[NARRATOR]** | In our final session for this module, we'll look at what happens *after* the click: **PCAP Analysis** for data exfiltration and the all-important **Ticketing Simulation** using the NIST framework. | **VISUAL:** End screen with a call to action for the lab and a preview of the next video's topic. |

### Video 1.3: PCAP Analysis and Ticketing Simulation

| Time | Speaker | Narration Script | Scene/Visual Description |
| :--- | :--- | :--- | :--- |
| **0:00** | **[NARRATOR]** | The user clicked the link. Now, the attacker is active on the network. We need to analyze the network traffic to see if they've established a Command and Control channel or if they're trying to exfiltrate data. We use **PCAP** files and **Wireshark** for this. | **VISUAL:** Diagram showing a compromised host sending traffic to an external C2 server. |
| **0:45** | **[NARRATOR]** | We're looking for anomalies. For a phishing attack, this might be a large HTTP POST request (data exfiltration) or frequent, small DNS queries to a suspicious domain (C2 beaconing). We use Wireshark filters to cut through the noise. | **DEMO:** Analyst opens Wireshark with a sample PCAP. They apply the filter `http.request.method == POST and http.content_length > 10000` to find a large data transfer. |
| **1:45** | **[NARRATOR]** | Once we have the full picture, we must document it using the **NIST 800-61 Incident Response Framework**. This is the industry standard. It has four phases: Preparation, Detection & Analysis, Containment, Eradication & Recovery, and Post-Incident Activity. | **VISUAL:** Animated graphic of the **NIST 800-61 Lifecycle**, highlighting the four phases. |
| **2:30** | **[NARRATOR]** | Our focus is on the **Containment** and **Analysis** phases. In the ticketing system, we document the IOCs, the timeline, and the actions we took—like isolating the host or blocking the malicious IP. This ticket is the official record of the incident. | **DEMO:** Analyst fills out a simulated incident ticket template, showing where to put the IOCs, the timeline, and the containment actions. |
| **3:30** | **[NARRATOR]** | **LAB WALKTHROUGH:** You will analyze a PCAP file from a simulated phishing breach. You'll find the C2 connection, identify the exfiltrated data size, and then complete a full incident ticket using the provided template. This is your first portfolio-ready project: the **Phishing Triage Playbook**. | **DEMO:** Quick screen-cap showing the final incident ticket and the Phishing Triage Playbook document. |
| **4:30** | **[NARRATOR]** | **Secretary-Style Summary:** PCAP analysis reveals post-compromise activity. Use Wireshark to filter for anomalies like large POSTs or C2 beaconing. Document the entire process using the NIST 800-61 framework in your incident ticket. | **VISUAL:** A clean, concise **Secretary-Style Summary** text box appears on screen. |
| **5:00** | **[NARRATOR]** | Congratulations on completing Module 1! You now have the foundational skills for phishing triage. Next, we move to **Module 2: Unauthorized Access**, where we dive deep into host logs and cloud IAM investigations. | **VISUAL:** End screen with a call to action for the final project and a preview of Module 2. |

---

## Video Script Template for Remaining Modules (2-8)

The remaining modules will follow the same structured script format, ensuring consistency for the visual learner.

| Time | Speaker | Narration Script | Scene/Visual Description |
| :--- | :--- | :--- | :--- |
| **0:00** | **[INTRO MUSIC/TITLE CARD]** | | **TITLE CARD:** SOC Analyst I — From Cradle to Grave. **MODULE X:** [Module Title]. **LESSON X.Y:** [Lesson Title]. |
| **0:30** | **[NARRATOR]** | **[Introduction to the attack type/concept, its impact, and why it matters to a SOC Analyst.]** | **VISUAL:** Animated diagram of the attack chain (e.g., Privilege Escalation Flow, Malware Execution Chain). |
| **1:15** | **[NARRATOR]** | **[Detailed explanation of the core technical concept, e.g., how Linux `auth.log` works, or the structure of a YARA rule.]** | **VISUAL:** Static diagram or chart (e.g., **Linux Log File Structure**, **YARA Rule Syntax Breakdown**). |
| **2:00** | **[NARRATOR]** | **[Focus on the practical detection methods and tools, e.g., Volatility commands, Suricata rule keywords, CloudTrail event names.]** | **VISUAL:** **Cheat Sheet** graphic appears on screen (e.g., **Key CloudTrail Event Names**). |
| **2:45** | **[NARRATOR]** | **LAB WALKTHROUGH:** **[Guided, step-by-step demonstration of the lab exercise. Focus on command-line tools or web console navigation.]** | **DEMO:** Screen recording of the analyst executing commands (e.g., `vol.py -f mem.dmp pslist`) or navigating the AWS console. |
| **3:45** | **[NARRATOR]** | **Secretary-Style Summary:** **[Concise, dense summary of the key takeaways and action items for the lesson.]** | **VISUAL:** A clean, concise **Secretary-Style Summary** text box appears on screen. |
| **4:15** | **[NARRATOR]** | **[Wrap-up and call to action for the lab/project. Preview of the next video's topic.]** | **VISUAL:** End screen with a call to action for the lab and a preview of the next video's topic. |

---


---

## Hands-On Labs, Portfolio Projects, and Capstone Challenges

This section provides detailed, step-by-step labs and projects for each module. Labs are designed to be completed in 1-2 hours using open-source tools and synthetic data.

### Module 1: Phishing Attack — Labs and Projects

#### Lab 1.1: Email Header Analysis and Spoofing Detection

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

1. Copy the sample header into a text editor. Read the `Received` lines from bottom to top. Identify the first server that received the email: `attacker.malicious.net [198.51.100.50]`.

2. Check the `X-Originating-IP`. It matches the attacker's IP: `198.51.100.50`. This is a red flag.

3. Examine the `Received-SPF` line. It shows `fail`, meaning the email did not pass SPF validation. The domain `amazon-security.com` does not authorize `198.51.100.50` to send emails on its behalf.

4. Check the `From` address: `noreply@amazon-security.com`. This looks legitimate, but we've already identified the true origin as `attacker.malicious.net`.

5. **Conclusion:** This email is spoofed. The attacker registered a domain similar to Amazon's (`amazon-security.com` instead of `amazon.com`) and sent the email from their own server. The SPF failure confirms this.

**Deliverable:** A one-page analysis document identifying the spoofing indicators and explaining why this email is malicious.

---

#### Lab 1.2: OSINT Threat Enrichment

**Objective:** Enrich the IOCs from the spoofed email with threat intelligence.

**IOCs to Investigate:**

- Domain: `amazon-security.com`
- IP Address: `198.51.100.50`
- Email: `noreply@amazon-security.com`

**Lab Steps:**

1. **VirusTotal Domain Check:** Visit `virustotal.com` and search for `amazon-security.com`. Document the creation date, registrar, and any security vendor detections.

2. **Whois Lookup:** Use a Whois tool (e.g., `whois.com` or command-line `whois`) to check the domain registration. Look for the registrant name, creation date, and registrar. A newly registered domain (within days of the phishing email) is a strong indicator of malicious intent.

3. **Shodan IP Search:** Use `shodan.io` to search for the IP address `198.51.100.50`. Document any open ports, services, or hosting provider information.

4. **AbuseIPDB Check:** Visit `abuseipdb.com` and search for `198.51.100.50`. Look for historical abuse reports and the confidence score.

5. **Email Reputation:** Check if the email address `noreply@amazon-security.com` has been reported on email reputation services.

**Deliverable:** A threat enrichment report documenting all findings from the four OSINT tools, including creation dates, reputation scores, and historical abuse reports.

---

#### Lab 1.3: PCAP Analysis and Incident Ticket Creation

**Objective:** Analyze network traffic from a phishing compromise and create an incident ticket.

**Scenario:** A user clicked the malicious link in the phishing email. The attacker's malware established a C2 connection and exfiltrated a small amount of data.

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

1. **Analyze the PCAP:** Identify the key events in the traffic. The user's computer (`192.168.1.100`) first queries for the phishing domain (`amazon-security.com`), then connects to the attacker's server (`203.0.113.45`), downloads malware, and then establishes a C2 connection to `198.51.100.50`.

2. **Extract IOCs:** Document all IOCs: domains, IP addresses, and URLs.

3. **Create a Timeline:** Order the events chronologically with timestamps.

4. **Determine the Scope:** The compromised host is `192.168.1.100`. Check if any other hosts on the network have similar traffic patterns.

5. **Create an Incident Ticket:** Using the provided template, document the incident with all IOCs, timeline, and recommended containment actions.

**Incident Ticket Template:**

```
INCIDENT TICKET
===============

Title: Phishing Email with Malware Delivery and C2 Establishment

Severity: HIGH

Summary:
A user received a phishing email spoofing Amazon Security. The email contained a malicious link that delivered malware to the user's computer. The malware established a C2 connection to an external server and exfiltrated data.

IOCs:
- Malicious Domain: amazon-security.com (Registrant: [REDACTED], Created: [DATE])
- Attacker IP: 198.51.100.50 (Hosted by: [PROVIDER], Abuse Reports: [COUNT])
- C2 Server: 198.51.100.50:80
- Malware Download URL: http://203.0.113.45/verify.php
- Compromised Host: 192.168.1.100 (User: [USERNAME])

Timeline:
- 2024-01-15 10:30:45: Phishing email received
- 2024-01-15 10:31:00: User clicks malicious link
- 2024-01-15 10:31:05: Malware downloaded from 203.0.113.45
- 2024-01-15 10:31:10: Malware executed on 192.168.1.100
- 2024-01-15 10:32:00: C2 beacon sent to 198.51.100.50
- 2024-01-15 10:32:30: Data exfiltration (2 MB) to 198.51.100.50

Actions Taken:
1. Isolated host 192.168.1.100 from the network
2. Blocked IP 198.51.100.50 at the firewall
3. Blocked domain amazon-security.com at the DNS level
4. Initiated malware analysis on the downloaded file

Recommended Next Steps:
1. Perform memory forensics on the compromised host
2. Search for similar C2 traffic from other hosts
3. Notify the user and reset their credentials
4. Conduct a full disk forensics analysis
5. Determine what data was exfiltrated

Assigned To: [SOC Analyst Name]
Status: OPEN
```

**Deliverable:** A completed incident ticket with all IOCs, timeline, and recommended actions.

---

#### Portfolio Project 1.1: Phishing Triage Playbook

**Objective:** Create a comprehensive, reusable playbook for phishing triage that can be shared on LinkedIn.

**Deliverable Structure:**

The playbook should include the following sections:

1. **Executive Summary:** A one-paragraph overview of the phishing incident, including the attack vector, impact, and resolution.

2. **Incident Details:** A detailed description of the phishing email, the malicious domain, and the attacker's infrastructure.

3. **Investigation Process:** A step-by-step walkthrough of how the incident was investigated, including email header analysis, OSINT, and PCAP analysis.

4. **Key Findings:** A summary of the IOCs, the attack timeline, and the scope of the breach.

5. **Containment Actions:** A list of the immediate actions taken to contain the threat.

6. **Recommendations:** A list of long-term recommendations to prevent similar incidents.

7. **Appendices:** Raw data (email headers, PCAP excerpts, OSINT reports) for reference.

**LinkedIn Presentation Tips:**

- Write in a clear, professional manner suitable for a technical audience.
- Use diagrams and tables to visualize the attack chain and timeline.
- Highlight the key technical skills demonstrated (email header analysis, OSINT, PCAP analysis, incident response).
- Include a brief reflection on what was learned and how it will improve future incident response.

---

### Module 5: Malware Attack — Labs and Projects

#### Lab 5.1: Static Malware Analysis

**Objective:** Perform static analysis on a malware sample to extract IOCs and determine the malware type.

**Synthetic Malware Sample (Simulated):**

For this lab, we'll use a fictional malware sample with the following characteristics:

- **File Name:** `invoice_2024.exe`
- **File Size:** 156 KB
- **MD5 Hash:** `d41d8cd98f00b204e9800998ecf8427e`
- **SHA-256 Hash:** `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

**Lab Steps:**

1. **Extract Strings:** Use the `strings` command to extract readable text from the binary. Look for hardcoded IP addresses, URLs, registry keys, or API calls.

   ```bash
   strings invoice_2024.exe | grep -E '(http|\.exe|\.dll|HKEY)'
   ```

   **Expected Output (Fictional):**

   ```
   http://malware-c2.net/beacon
   C:\Windows\System32\svchost.exe
   HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Run
   cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ...
   ```

2. **Analyze File Metadata:** Use the `file` command and `exiftool` to extract metadata.

   ```bash
   file invoice_2024.exe
   exiftool invoice_2024.exe
   ```

   **Expected Output:**

   ```
   invoice_2024.exe: PE32 executable (GUI) Intel 80386, for MS Windows
   Compiler: Microsoft Visual C++ 14.0
   Created: 2024-01-10 15:30:00
   ```

3. **Calculate Hashes:** Generate MD5, SHA-1, and SHA-256 hashes for reputation checking.

   ```bash
   md5sum invoice_2024.exe
   sha256sum invoice_2024.exe
   ```

4. **Check VirusTotal:** Paste the hashes into VirusTotal to check if the malware is known. Document the number of detections and the malware family names.

5. **Extract IOCs:** Document all IOCs found: C2 IP/domain, registry keys, file paths, and API calls.

**Deliverable:** A static analysis report documenting all extracted IOCs and initial malware classification.

---

#### Lab 5.2: Memory Forensics with Volatility

**Objective:** Analyze a memory dump from an infected system to identify malicious processes and network connections.

**Synthetic Memory Dump Scenario:**

A Windows 10 system was suspected of being infected. A memory dump was captured. We'll analyze it using the Volatility Framework.

**Lab Steps:**

1. **Identify the Operating System:** Use Volatility to determine the OS version and build.

   ```bash
   vol.py -f memory.dmp imageinfo
   ```

   **Expected Output:**

   ```
   Suggested Profile(s) : Win10x64_19041
   ```

2. **List Running Processes:** Use the `pslist` plugin to list all running processes.

   ```bash
   vol.py -f memory.dmp --profile=Win10x64_19041 pslist
   ```

   **Expected Output (Excerpt):**

   ```
   Offset(V)          Name                    PID   PPID   Thds   Hnds   Time
   0xffff8a8c2e3a0080 System                  4     0      157    2634   2024-01-15 10:00:00 UTC+0000
   0xffff8a8c2e3b0080 svchost.exe             456   4      8      245    2024-01-15 10:00:05 UTC+0000
   0xffff8a8c2e3c0080 explorer.exe            1200  456    45     1234   2024-01-15 10:00:10 UTC+0000
   0xffff8a8c2e3d0080 malware.exe             2456  1200   3      89     2024-01-15 10:30:45 UTC+0000  <-- SUSPICIOUS
   ```

3. **Identify Suspicious Processes:** Look for processes with unusual parent-child relationships (e.g., `explorer.exe` spawning `malware.exe`) or processes with names that mimic system processes (e.g., `svchost.exe` with unusual spelling).

4. **Analyze Network Connections:** Use the `connscan` plugin to find network connections.

   ```bash
   vol.py -f memory.dmp --profile=Win10x64_19041 connscan
   ```

   **Expected Output (Excerpt):**

   ```
   Offset(V)       Local Address             Remote Address            State
   0xffff8a8c2e4a0080 192.168.1.100:49152     198.51.100.50:80         ESTABLISHED
   ```

5. **Identify Injected Code:** Use the `malfind` plugin to find code injection.

   ```bash
   vol.py -f memory.dmp --profile=Win10x64_19041 malfind
   ```

   **Expected Output (Excerpt):**

   ```
   Process: malware.exe PID: 2456
   Address: 0x400000
   Flags: PAGE_EXECUTE_READWRITE
   [Injected Code Detected]
   ```

6. **Extract Suspicious Process:** Dump the suspicious process to disk for further analysis.

   ```bash
   vol.py -f memory.dmp --profile=Win10x64_19041 procdump -p 2456 -D ./dump/
   ```

**Deliverable:** A memory forensics report documenting all suspicious processes, network connections, and injected code.

---

#### Portfolio Project 5.1: Malware Triage Summary Report

**Objective:** Create a comprehensive malware analysis report suitable for a professional portfolio.

**Report Structure:**

1. **Executive Summary:** A one-paragraph overview of the malware, its threat level, and key findings.

2. **File Information:** Hash values, file size, file type, and compilation date.

3. **Static Analysis Findings:** Extracted strings, metadata, and initial IOCs.

4. **Dynamic Analysis Findings:** Behavioral observations from sandbox execution (file system changes, registry modifications, network connections).

5. **Memory Forensics Findings:** Suspicious processes, injected code, and network connections from memory analysis.

6. **Reverse Engineering Findings:** (Optional) Key functions and code patterns identified during disassembly.

7. **Malware Family Classification:** Identification of the malware family and comparison with known variants.

8. **MITRE ATT&CK Mapping:** Mapping of observed behaviors to MITRE ATT&CK tactics and techniques.

9. **Threat Assessment:** Severity rating, impact assessment, and affected systems.

10. **Recommendations:** Containment, eradication, and prevention recommendations.

11. **Appendices:** Raw data (strings output, memory dump excerpts, PCAP data) for reference.

**LinkedIn Presentation Tips:**

- Emphasize the end-to-end analysis process (static → dynamic → memory forensics).
- Use screenshots and diagrams to illustrate key findings.
- Highlight the technical tools and skills demonstrated.
- Include a reflection on the malware's sophistication and evasion techniques.

---

### Module 6: Detection Engineering — Labs and Projects

#### Lab 6.1: Suricata Rule Creation and Testing

**Objective:** Write a Suricata rule to detect a specific attack pattern and test it against a PCAP file.

**Attack Pattern to Detect:** HTTP requests to known malicious domains.

**Suricata Rule:**

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Potential Malware C2 Communication";
    flow:to_server,established;
    content:"GET";
    http_method;
    content:"malware-c2.net";
    http_host;
    sid:1000001;
    rev:1;
    classtype:trojan-activity;
    priority:1;
)
```

**Rule Explanation:**

- `alert http`: Generate an alert for HTTP traffic.
- `$HOME_NET any -> $EXTERNAL_NET any`: Match traffic from internal networks to external networks.
- `flow:to_server,established`: Only match established connections going to the server.
- `content:"GET"; http_method;`: Match HTTP GET requests.
- `content:"malware-c2.net"; http_host;`: Match requests to the domain "malware-c2.net".
- `sid:1000001`: Unique signature ID.
- `classtype:trojan-activity`: Classification for the alert.

**Lab Steps:**

1. **Create the Rule File:** Save the rule to a file named `malware-c2.rules`.

2. **Create a Test PCAP:** Use a tool like `tcpdump` or `scapy` to create a PCAP file containing HTTP traffic to "malware-c2.net".

   ```python
   from scapy.all import *
   
   # Create a packet with HTTP GET request to malware-c2.net
   pkt = IP(dst="203.0.113.45")/TCP(dport=80)/Raw(load="GET / HTTP/1.1\r\nHost: malware-c2.net\r\n\r\n")
   wrpcap("test.pcap", pkt)
   ```

3. **Run Suricata:** Execute Suricata against the test PCAP.

   ```bash
   suricata -r test.pcap -S malware-c2.rules -l ./logs/
   ```

4. **Verify the Alert:** Check the alert log to confirm the rule triggered.

   ```bash
   cat ./logs/eve.json | grep "malware-c2.net"
   ```

5. **Tune the Rule:** Adjust the rule to reduce false positives (e.g., add additional conditions).

**Deliverable:** A documented Suricata rule with test results and tuning notes.

---

#### Lab 6.2: YARA Rule Creation and Malware Detection

**Objective:** Write a YARA rule to detect a specific malware family and test it against known samples.

**Malware Family:** Fictional ransomware "CryptoLocker-like" malware.

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

**Rule Explanation:**

- `meta`: Metadata about the rule (description, author, date).
- `strings`: Patterns to search for (literal strings, regular expressions, hex patterns).
- `condition`: Logic for matching (all strings, at least 2 of 3, etc.).

**Lab Steps:**

1. **Create the Rule File:** Save the rule to a file named `cryptolocker.yar`.

2. **Create Test Malware Samples:** Create or download known CryptoLocker samples (or use the synthetic samples provided in the course).

3. **Run YARA:** Scan files or directories with the YARA rule.

   ```bash
   yara cryptolocker.yar /path/to/samples/
   ```

4. **Verify Detections:** Check the output for matches.

   ```
   CryptoLocker_Variant /path/to/samples/malware.exe
   ```

5. **Test for False Positives:** Scan benign files to ensure the rule doesn't produce false positives.

**Deliverable:** A documented YARA rule with test results and false positive analysis.

---

#### Portfolio Project 6.1: Detection Rule Pack v1

**Objective:** Create a set of 5 detection rules (Suricata, YARA, or Sigma) for a specific threat.

**Threat Selection:** APT-style lateral movement using PsExec.

**Rule Set:**

1. **Suricata Rule:** Detect PsExec traffic (port 445 with specific SMB signatures).
2. **Suricata Rule:** Detect suspicious PowerShell execution over the network.
3. **YARA Rule:** Detect PsExec binary by file signature.
4. **Sigma Rule:** Detect Windows Event Log entries for service creation (lateral movement indicator).
5. **Sigma Rule:** Detect unusual process execution patterns (parent-child relationships).

**Deliverable Structure:**

- A documented rule pack with all 5 rules.
- Test cases for each rule (PCAP files, malware samples, log entries).
- Test results showing successful detections and false positive analysis.
- A brief explanation of how these rules work together to detect lateral movement.

**LinkedIn Presentation Tips:**

- Emphasize the end-to-end detection strategy (network + host + log-based detection).
- Use a diagram showing how the rules complement each other.
- Include test results and false positive metrics.
- Highlight the value of a layered detection approach.

---

### Module 7: Live Attack & Defense — Capstone Challenges

#### Capstone Lab 7.1: Multi-Stage Attack Simulation

**Objective:** Analyze a complete, multi-stage attack scenario and perform end-to-end incident response.

**Attack Scenario:**

A user received a phishing email with a malicious Excel attachment. The attachment contained a macro that executed PowerShell code. The PowerShell code downloaded a second-stage malware that established a C2 connection. The attacker then performed reconnaissance, escalated privileges, and exfiltrated sensitive data.

**Provided Data:**

- Phishing email (raw format)
- Malicious Excel file (for static analysis)
- Network traffic capture (PCAP) showing the attack stages
- Host logs (Windows Event Log and Syslog) from the compromised system
- AWS CloudTrail logs showing cloud resource access
- Memory dump from the compromised system

**Lab Steps:**

1. **Phase 1: Detection & Analysis**
   - Analyze the phishing email to identify the attack vector.
   - Extract the malicious Excel file and perform static analysis.
   - Analyze the PCAP to identify the C2 communication and data exfiltration.
   - Review host logs to identify the attack timeline and scope.

2. **Phase 2: Containment**
   - Identify the compromised host and user account.
   - Determine the scope of the breach (other systems affected, data accessed).
   - Recommend immediate containment actions (isolate host, disable account, block C2 IP).

3. **Phase 3: Eradication & Recovery**
   - Identify all persistence mechanisms (scheduled tasks, registry modifications, backdoors).
   - Recommend eradication steps (remove malware, reset credentials, patch vulnerabilities).
   - Recommend recovery steps (restore from backup, rebuild system).

4. **Phase 4: Post-Incident**
   - Create a comprehensive incident report with timeline, findings, and recommendations.
   - Identify lessons learned and recommendations for preventing similar incidents.

**Deliverable:** A comprehensive incident report (10-15 pages) documenting all phases of the incident response.

---

#### Capstone Project 7.1: Full Incident Report with Timeline

**Objective:** Create a professional, LinkedIn-ready incident report documenting a complete incident.

**Report Structure:**

1. **Executive Summary:** A one-page overview suitable for C-level executives.
2. **Incident Details:** Complete description of the attack, including timeline, scope, and impact.
3. **Investigation Findings:** Detailed technical findings from each phase of the investigation.
4. **Root Cause Analysis:** Explanation of how the attack succeeded and what vulnerabilities were exploited.
5. **Impact Assessment:** Quantification of the impact (systems affected, data accessed, downtime).
6. **Containment Actions:** Detailed description of actions taken to stop the attack.
7. **Eradication & Recovery:** Steps taken to remove the attacker's presence and restore systems.
8. **Lessons Learned:** Recommendations for preventing similar incidents.
9. **Appendices:** Raw data (logs, PCAP excerpts, screenshots) for reference.

**LinkedIn Presentation Tips:**

- Write in a clear, professional manner suitable for both technical and non-technical audiences.
- Use diagrams to visualize the attack chain and timeline.
- Emphasize the end-to-end incident response process.
- Highlight the technical skills demonstrated (log analysis, PCAP analysis, malware analysis, threat hunting).
- Include a reflection on the incident and lessons learned.

---

#### Capstone Challenge 7.2: Detect & Defend Challenge

**Objective:** Develop detection logic, investigate suspicious activity, and generate a SOC-ready report under time pressure.

**Challenge Format:**

You are given 2 hours to complete the following tasks:

1. **Detection Development (30 minutes):** Write 2-3 detection rules (Suricata, YARA, or Sigma) to detect the attack pattern.

2. **Investigation (60 minutes):** Analyze provided logs (PCAP, host logs, cloud logs) to identify the attack, create a timeline, and determine the scope.

3. **Reporting (30 minutes):** Create a one-page incident summary suitable for management, including the current status, affected systems, and recommended immediate actions.

**Deliverable:** Detection rules, investigation notes, and executive incident summary.

---

### Synthetic Suricata and YARA Data Examples

#### Synthetic Suricata Alert Log (eve.json format)

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

#### Synthetic YARA Detection Output

```
CryptoLocker_Variant /tmp/samples/malware_001.exe
CryptoLocker_Variant /tmp/samples/malware_002.exe
PsExec_Lateral_Movement /tmp/samples/psexec.exe
```

---


---

## SOC Documentation Templates

Professional documentation is a cornerstone of effective SOC operations. These templates provide a standardized structure for common incident response and detection engineering tasks.

### Template 1: Incident Report Template (NIST 800-61 Aligned)

| Section | Key Information to Include | Audience |
| :--- | :--- | :--- |
| **1. Executive Summary** | **(1-2 Paragraphs)** Incident title, date/time discovered, current status, business impact, and key findings. **MUST** be non-technical. | Executive Management |
| **2. Incident Details** | **Type:** (e.g., Phishing, Unauthorized Access, Malware). **Severity:** (e.g., High, Medium). **Affected Assets:** (Hostnames, IPs, User Accounts). **Discovery Method:** (e.g., SIEM Alert, User Report). | SOC Team, Management |
| **3. Timeline of Events** | Chronological list of key events with timestamps (UTC preferred). **MUST** include: Initial Access, Detection, Containment, Eradication, and Recovery. | SOC Team, Forensics |
| **4. Investigation Findings** | **Technical Analysis:** IOCs (IPs, Hashes, Domains), Log Analysis (Key log entries), Malware Analysis Summary (if applicable). **Scope:** How many systems/users were affected. | SOC Team, Forensics |
| **5. Containment, Eradication, & Recovery** | Detailed steps taken for each phase. **Containment:** (e.g., Host isolation, Account suspension). **Eradication:** (e.g., Malware removal, Patching). **Recovery:** (e.g., System restoration, Monitoring). | SOC Team, IT Operations |
| **6. Root Cause Analysis (RCA)** | The underlying vulnerability or failure that allowed the incident (e.g., unpatched software, weak password, lack of MFA). | Management, IT Operations |
| **7. Lessons Learned & Recommendations** | **Short-Term:** Immediate configuration changes. **Long-Term:** Policy changes, training needs, new security tool acquisition. | Management, IT Operations |
| **8. Appendices** | Raw IOC list, screenshots, raw log excerpts, full memory analysis report link. | Forensics |

---

### Template 2: Phishing Response Template

**Purpose:** A quick-reference checklist and documentation for a Tier 1 analyst handling a reported phishing email.

| Step | Action | Status (Y/N/NA) | Notes/IOCs |
| :--- | :--- | :--- | :--- |
| **1. Triage & Validation** | Isolate the email (move to quarantine/sandbox). | | |
| | Extract the raw email header. | | |
| | Check SPF/DKIM/DMARC results in the header. | | |
| | Check the `X-Originating-IP` against internal ranges. | | |
| **2. Threat Enrichment (OSINT)** | Check all domains/IPs on VirusTotal. | | |
| | Check all domains/IPs on AbuseIPDB/Whois. | | |
| | Is the domain newly registered (less than 90 days)? | | |
| **3. User Interaction Check** | Did the user click the link or open the attachment? | | |
| | If yes, isolate the user's host immediately. | | |
| | Reset the user's password and enforce MFA. | | |
| **4. Containment & Eradication** | Block malicious domains/IPs at the firewall/proxy. | | |
| | Remove the email from all other user inboxes. | | |
| | Initiate host-based forensics on the compromised machine. | | |
| **5. Documentation** | Create a formal Incident Ticket (using Template 1). | | |
| | Notify the Security Awareness team for user re-training. | | |

---

### Template 3: Malware Analysis Summary Template

**Purpose:** A concise report summarizing the findings of static and dynamic malware analysis.

| Field | Data Point |
| :--- | :--- |
| **File Name & Path** | |
| **MD5 / SHA256 Hash** | |
| **File Type** | (e.g., PE32 Executable, PDF, Script) |
| **Malware Family** | (e.g., Emotet, TrickBot, Ransomware) |
| **Static Analysis Findings** | (e.g., Obfuscated strings, Compiler used, Embedded resources) |
| **Dynamic Analysis Findings** | **Persistence:** (e.g., Registry Run Key, Scheduled Task). **Network:** (C2 IP/Domain, Port). **Host Changes:** (e.g., Files dropped, Registry keys modified). |
| **Key IOCs** | **IPs:** |
| | **Domains:** |
| | **File Paths:** |
| **MITRE ATT&CK Mapping** | (e.g., T1071.001 - Application Layer Protocol) |
| **Severity & Confidence** | (e.g., High/Confirmed) |
| **Recommended Action** | (e.g., Block C2, Deploy YARA rule, Eradicate from host) |

---

### Template 4: Cloud Incident Triage Template (AWS Focus)

**Purpose:** A structured approach to investigating suspicious activity in the AWS environment.

| Step | Action | AWS Log Source | Key Event/Indicator |
| :--- | :--- | :--- | :--- |
| **1. Initial Alert** | Identify the affected IAM User/Role and the time of the alert. | GuardDuty, CloudWatch | GuardDuty Finding ID, `EventTime` |
| **2. IAM Credential Check** | Check for unauthorized `CreateAccessKey` or `UpdateAccessKey` calls. | CloudTrail | `CreateAccessKey`, `UpdateAccessKey` |
| **3. Privilege Escalation** | Check for `AttachUserPolicy` or `CreatePolicyVersion` calls on the compromised user. | CloudTrail | `AttachUserPolicy`, `CreatePolicyVersion` |
| **4. Reconnaissance** | Check for excessive `ListBuckets`, `DescribeInstances`, or `GetCallerIdentity` calls. | CloudTrail | High volume of read-only API calls |
| **5. Data Exfiltration** | Check for high volume of `GetObject` or `PutObject` calls to S3 from an unusual IP. | S3 Access Logs, CloudTrail | `GetObject`, `PutObject` |
| **6. Containment** | Immediately disable the compromised IAM User/Role and revoke all associated access keys. | IAM Console | `UpdateUser` (Status: Inactive) |
| **7. Network Analysis** | Check VPC Flow Logs for connections to known malicious external IPs. | VPC Flow Logs | High volume of traffic to external IP |

---

### Template 5: Detection Rule Development Template

**Purpose:** Standardized documentation for creating and deploying new detection logic (Suricata, YARA, Sigma).

| Field | Description | Example |
| :--- | :--- | :--- |
| **Rule Name** | Concise, descriptive name for the detection. | `WIN_Suspicious_PowerShell_Execution` |
| **Rule ID (SID)** | Unique identifier for the rule. | `1000005` |
| **Threat Category** | MITRE ATT&CK Tactic/Technique. | T1059.001 (PowerShell) |
| **Log Source** | Where the rule is applied (Host, Network, Cloud). | Windows Event Log (Security) |
| **Detection Logic** | The core condition(s) of the rule (in plain English). | Detects `EventID 4688` where `ProcessName` is `powershell.exe` and `CommandLine` contains `IEX` or `EncodedCommand`. |
| **Rule Code** | The actual code (Sigma YAML, Suricata Rule, YARA Rule). | `selection: EventID: 4688, CommandLine: '*IEX*'` |
| **Test Case** | The specific action/data used to validate the rule. | Execute `powershell.exe -e <base64_string>` |
| **False Positive Analysis** | Potential sources of false positives and how they were tuned out. | Excluded known administrative scripts. |
| **Deployment Status** | (e.g., Testing, Staging, Production) | |

---

## Career & Interview Prep Package

### 30 Common SOC Interview Questions

#### Technical Questions (Tier 1 & Tier 2 Focus)

1.  Walk me through the steps you would take to investigate a high-severity phishing alert.
2.  What is the difference between a **false positive** and a **false negative**? Which is more dangerous in a SOC?
3.  Explain the **NIST Incident Response Lifecycle** (Preparation, Detection & Analysis, Containment, Eradication & Recovery, Post-Incident).
4.  What are the key differences between **IDS** (Intrusion Detection System) and **IPS** (Intrusion Prevention System)?
5.  What are the three main pieces of information you look for when analyzing an **email header**?
6.  How would you use **Wireshark** to detect a large data exfiltration attempt? Give me a filter.
7.  What is **OSINT**, and what are three tools you would use to enrich an IOC?
8.  Explain the purpose of **YARA** rules and how they differ from **Suricata** rules.
9.  What is **memory forensics**, and what are two key artifacts you would look for in a memory dump?
10. What is a **C2** (Command and Control) channel, and how would you detect it?
11. What is the **MITRE ATT&CK Framework**, and how do you use it in your daily work?
12. How do you detect **lateral movement** on a network?
13. What are the most important log sources on a **Linux** server for security monitoring?
14. Explain the concept of **IAM** (Identity and Access Management) and how you would detect IAM abuse in **AWS CloudTrail** logs.
15. Define **Root Cause Analysis (RCA)** and why it is critical after an incident is closed.

#### Behavioral and Scenario Questions

16. **(STAR Method)** Tell me about a time you had to handle a high-pressure, high-severity incident.
17. **(STAR Method)** Describe a time you made a mistake during an investigation. How did you handle it?
18. **(STAR Method)** Tell me about a time you had to communicate a technical finding to a non-technical audience (like a manager or executive).
19. How do you stay up-to-date with the latest threats, vulnerabilities, and security news?
20. What is your process for handling a ticket that you cannot resolve?
21. Why do you want to work in a SOC, and what do you think is the most challenging part of the job?
22. How do you prioritize your workload when you have 10 high-severity alerts and 20 low-severity alerts?
23. What is your experience with **security automation** or scripting (e.g., Bash, Python)?
24. How would you handle a situation where a colleague is not following the established incident response procedure?
25. What are the key components of a good **incident report**?

### Whiteboard-Style IR Scenario

**Scenario:**

> It is 2:00 AM. Your SIEM fires a high-severity alert: **"Unusual Data Transfer from Internal Server to External IP (Known Malicious)."** The source is a critical Linux web server, and the destination IP is flagged on VirusTotal as a C2 server.
>
> **Your Task:** Walk me through your entire incident response process, from the moment the alert fires until the incident is closed. Be specific about the tools, commands, and containment actions you would take.

**Key Points to Cover in Your Walkthrough:**

1.  **Initial Triage:** Acknowledge the alert, verify the severity, and check the IOCs (IP, Server Name, User).
2.  **Detection & Analysis:**
    *   Check the Linux server's logs (`/var/log/syslog`, `journalctl`) for suspicious process execution or file access.
    *   Analyze the network flow data (NetFlow/PCAP) to confirm the volume and nature of the data transfer.
    *   Use OSINT on the external IP to confirm its malicious reputation.
3.  **Containment:**
    *   **Immediate Action:** Isolate the Linux server from the network (but keep it powered on for forensics).
    *   Block the external C2 IP at the firewall/proxy.
4.  **Eradication & Recovery:**
    *   Acquire a forensic image of the disk and a memory dump (using Volatility).
    *   Analyze the memory/disk to find the root cause (malware, compromised credentials).
    *   Once the root cause is found, eradicate it (remove malware, patch vulnerability, reset credentials).
    *   Restore the server to a clean state.
5.  **Post-Incident:** Create a full incident report, conduct a lessons-learned meeting, and implement new detection rules to prevent recurrence.

### Resume and LinkedIn Optimization

**1. Resume Optimization:**

*   **Focus on Quantifiable Achievements:** Instead of "Monitored SIEM alerts," write "Reduced false positive rate by 20% by tuning 50+ detection rules."
*   **Use Keywords:** Ensure your resume is rich with keywords from the job description: `NIST 800-61`, `PCAP Analysis`, `Linux`, `AWS CloudTrail`, `Suricata`, `YARA`, `Threat Hunting`.
*   **Highlight Portfolio Projects:** Dedicate a section to your "Cybersecurity Portfolio" and list the Capstone Projects from this course (e.g., "Full Incident Report on Multi-Stage Attack," "Detection Rule Pack v1").
*   **Technical Skills Section:** Group skills logically: **IR Tools** (Wireshark, Volatility), **Detection** (Suricata, YARA, Sigma), **OS/Cloud** (Linux, Windows, AWS).

**2. LinkedIn Optimization:**

*   **Headline:** Use a clear, goal-oriented headline: "Aspiring SOC Analyst | Incident Response & Detection Engineering | Building Portfolio with Linux, AWS, and YARA."
*   **About Section:** Use the first paragraph to tell your story (the "why") and the second to list your core technical competencies (the "what"). Mention your focus on **AI-augmented SOC tasks** and **cloud security**.
*   **Projects Section:** Use this section to showcase your portfolio projects. For each project, include a detailed description of the problem, your methodology, and the tools you used.
*   **Activity:** Engage with industry content. Share your thoughts on recent breaches or new threat intelligence. This demonstrates passion and current knowledge.

---
