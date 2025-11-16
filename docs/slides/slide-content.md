# SOC Analyst I — From Cradle to Grave: Course Presentation

## Slide 1: Title Slide
### SOC Analyst I — From Cradle to Grave
#### Practical Incident Response, Detection Engineering, and Career Readiness
---

## Slide 2: Course Goals: Become a Job-Ready SOC Analyst
### Key Learning Objectives
*   **Master Tier 1 Triage:** Handle Phishing, Malware, DDoS, and Unauthorized Access incidents.
*   **Deep-Dive Forensics:** Conduct host log, memory, and network traffic (PCAP) analysis.
*   **Detection Engineering:** Write and test rules using Suricata, YARA, and Sigma.
*   **Cloud Security:** Investigate incidents using AWS CloudTrail, GuardDuty, and VPC Flow Logs.
*   **Build a Portfolio:** Complete 16+ LinkedIn-ready projects and capstone challenges.
---

## Slide 3: Module 1: Phishing Attack — The Gateway Incident
### Phishing: The #1 SOC Threat
*   **Primary Access Vector:** Phishing is the most common starting point for breaches.
*   **Phishing Kill Chain:** Reconnaissance → Weaponization → Delivery → Exploitation → Post-Compromise.
*   **Triage Goal:** Rapidly identify malicious intent and contain the threat before user interaction.
*   **Visual Asset:** Diagram: **Phishing Kill Chain** (Simple 5-step flow chart).
---

## Slide 4: Module 1: Email Header Analysis
### Metadata is the Key to Truth
*   **Trace the Path:** Read `Received` lines from bottom to top to find the true origin.
*   **Focus on Origin:** Check `Return-Path` and `X-Originating-IP` for the sender's true source.
*   **Authentication Checks:** Verify SPF, DKIM, and DMARC results to detect domain spoofing.
*   **Action:** Preserve the raw header as evidence for the investigation.
*   **Visual Asset:** Cheat Sheet: **Email Header Field Guide** (Table mapping key fields to their investigative purpose).
---

## Slide 5: Module 1: OSINT for Threat Enrichment
### Adding Context to Indicators of Compromise (IOCs)
*   **VirusTotal:** The go-to for file hash and domain reputation checks. Look for multiple engine hits.
*   **Whois & Shodan:** Identify domain ownership (age, registrant) and exposed services on the attacker's IP.
*   **AbuseIPDB:** Check for historical abuse reports against the source IP address.
*   **Best Practice:** Use multiple sources for cross-validation; document all findings in the ticket.
*   **Visual Asset:** Diagram: **OSINT Tool Ecosystem** (Hub-and-spoke diagram with IOC in the center).
---

## Slide 6: Module 2: Unauthorized Access — IAM Abuse
### Detecting Privilege Escalation and Account Compromise
*   **Vectors:** Credential theft, weak passwords, insider threat, misconfiguration.
*   **Privilege Escalation:** Moving from a low-privilege user to a higher-privilege user (`root`, `Administrator`).
*   **AWS IAM Abuse:** Look for `CreateAccessKey`, `AttachUserPolicy`, or suspicious role assumption in CloudTrail.
*   **Detection Focus:** Spike in failed logins followed by a successful login from a new, unusual location.
*   **Visual Asset:** Workflow: **IAM Incident Triage** (Flowchart: Alert → Check CloudTrail → Suspend User → Revoke Keys).
---

## Slide 7: Module 2: Host Log Analysis
### Host Logs are the Most Granular Evidence
*   **Linux Sources:** `/var/log/auth.log` (authentication), `journalctl` (systemd events).
*   **Windows Sources:** Security Event Log (Event IDs 4624/4625 for login/logout).
*   **Timeline Creation:** Ordering all log events chronologically to reconstruct the attack narrative.
*   **Forensic Tools:** Use `grep`, `awk`, and `sed` for efficient log parsing on the command line.
*   **Visual Asset:** Template: **User Activity Timeline Format** (Table with columns: Timestamp, Source, Event, Description).
---

## Slide 8: Module 3: Data Loss / Exfiltration
### Identifying the "Bleeding" of Sensitive Data
*   **Exfiltration Channels:** HTTP/HTTPS, DNS Tunneling, Cloud Storage APIs, and ICMP.
*   **Detection Indicators:** Large file transfers, unusual data volume spikes, or connections to suspicious external hosts.
*   **Cloud Data Forensics:** S3 Access Logs and CloudTrail are the primary evidence sources for cloud exfil.
*   **DLP Strategy:** Identify sensitive data, monitor access, and block unauthorized transfers.
*   **Visual Asset:** Diagram: **Data Exfiltration Techniques Map** (Mind map of techniques categorized by protocol).
---

## Slide 9: Module 4: DDoS Attack — Availability and Resilience
### Attack Taxonomy and Detection
*   **DDoS Objective:** Deny service availability by overwhelming resources (bandwidth, CPU, application).
*   **Layer 3/4 Attacks:** Volumetric attacks (UDP/ICMP floods, SYN floods) targeting network infrastructure.
*   **Layer 7 Attacks:** Application-layer attacks (HTTP floods) targeting web server resources.
*   **Detection:** Look for massive spikes in traffic volume, high connection rates, and unusual source IP diversity.
*   **Visual Asset:** Diagram: **DDoS Attack Taxonomy** (Tree diagram classifying attacks by Layer 3/4 and Layer 7).
---

## Slide 10: Module 4: DDoS Mitigation
### Cloud-Native Defense Strategies
*   **Mitigation Strategies:** Rate Limiting, Traffic Filtering (ACLs), and Traffic Scrubbing.
*   **Cloud-Native Defense:** AWS Shield (always-on protection), WAF (Layer 7 filtering), CloudFront (caching/distribution).
*   **Triage Goal:** Differentiate legitimate traffic spikes from malicious traffic to avoid over-blocking.
*   **Post-Incident:** Analyze attack vectors to harden defenses and tune rate-limiting thresholds.
*   **Visual Asset:** Diagram: **Cloud DDoS Mitigation Architecture** (Traffic flow through CloudFront, WAF, and Shield).
---

## Slide 11: Module 5: Malware Attack — Triage and Analysis
### Static, Dynamic, and Memory Forensics
*   **Static Analysis:** Examining the file without execution (Strings, Hashes, Metadata).
*   **Dynamic Analysis:** Executing the malware in a controlled, isolated environment (sandbox).
*   **Memory Forensics:** Analyzing RAM (Volatility Framework) to find volatile evidence (processes, injected code).
*   **Reverse Engineering (Basics):** Analyzing the binary code to understand its function and intent (Ghidra/IDA).
*   **Visual Asset:** Diagram: **Malware Triage Flow** (Flowchart: Submission → Static → Dynamic → Reporting).
---

## Slide 12: Module 6: Detection Engineering — Building Defenses
### The Detection Lifecycle
*   **Lifecycle:** Identify → Develop → Test → Deploy → Tune.
*   **Suricata (Network):** Open-source IDS/IPS. Uses rules to inspect network traffic (`content`, `sid`).
*   **YARA (Host/File):** Pattern matching for identifying and classifying malware files (`strings`, `condition`).
*   **Sigma (Log/SIEM):** Generic signature format for log events. Write once, convert to many SIEM queries.
*   **Visual Asset:** Diagram: **Detection Engineering Lifecycle** (Circular diagram showing the 5 stages).
---

## Slide 13: Module 7: Live Attack & Defense — Capstone Simulation
### End-to-End Incident Response
*   **Multi-Stage Attack:** A sequence of TTPs mapped using the MITRE ATT&CK framework.
*   **Live Triage:** Rapidly analyzing alerts and logs from multiple sources (host, network, cloud).
*   **Containment:** Stop the attack (Isolate host, disable account, block C2 IP).
*   **Eradication & Recovery:** Remove persistence and restore systems to a clean state.
*   **Visual Asset:** Diagram: **Multi-Stage Attack Chain (MITRE Mapping)** (Flowchart showing TTPs mapped to MITRE stages).
---

## Slide 14: Module 7: Capstone Challenge
### The 10-Minute Incident Summary
*   **Rapid Reporting:** Essential for executive communication during a crisis.
*   **Focus:** Business impact, scope, and immediate actions—not technical minutiae.
*   **The "Secretary Summary":** Concise, dense, and actionable information for decision-makers.
*   **Deliverable:** A clear, one-page brief under pressure.
*   **Visual Asset:** Template: **Executive Incident Briefing Template** (One-page layout with clear sections).
---

## Slide 15: Module 8: SOC Interview Simulation
### Career Readiness and Roadmap
*   **Technical Prep:** Master the fundamentals of IR, networking, Linux, and cloud security (30 common questions).
*   **Behavioral Prep:** Use the **STAR Method** (Situation, Task, Action, Result) for structured answers.
*   **Whiteboard Scenarios:** Demonstrate your thought process (Detection → Containment → Eradication → Reporting).
*   **Roadmap:** Plan your progression from Tier 1 → Tier 2 → Specialist (Cloud/Threat Hunting).
*   **Visual Asset:** Diagram: **STAR Method Breakdown** (Visual guide to the four components).
---

## Slide 16: Next Steps: Your 90-Day Action Plan
### Immediate Focus: Portfolio Building
*   **Weeks 1-4:** Phishing & Unauthorized Access (Labs 1.1-2.3).
*   **Weeks 5-8:** Data Loss, DDoS, & Malware (Labs 3.1-5.2).
*   **Weeks 9-12:** Detection Engineering & Capstone (Labs 6.1-7.2).
*   **Goal:** Complete all 16+ portfolio projects to showcase on LinkedIn.
*   **Visual Asset:** Table: **90-Day Study Schedule** (Timeline with Milestones: Certifications, Projects, Role Transition).
---

## Slide 17: Thank You & Q&A
### Manus AI
#### SOC Analyst I — From Cradle to Grave
---
