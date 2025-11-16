// lab-data.js - Lab content data structure
const labData = {
  '1.1': {
    module: 1,
    title: 'Email Header Analysis and Spoofing Detection',
    objective: 'Extract and analyze email headers to identify spoofing and determine the true origin of an email.',
    duration: '1 hour',
    difficulty: 'Intermediate',
    tools: ['Text Editor', 'Header Analyzer', 'MXToolbox'],
    deliverable: 'A one-page analysis document identifying spoofing indicators',
    status: 'in-progress'
  },
  '1.2': {
    module: 1,
    title: 'OSINT Threat Enrichment',
    objective: 'Enrich the IOCs from the spoofed email with threat intelligence using open-source tools.',
    duration: '1 hour',
    difficulty: 'Beginner',
    tools: ['VirusTotal', 'AbuseIPDB', 'Shodan', 'Whois'],
    deliverable: 'Threat enrichment report with findings from all OSINT tools',
    status: 'available'
  },
  '1.3': {
    module: 1,
    title: 'PCAP Analysis and Incident Ticket Creation',
    objective: 'Analyze network traffic from a phishing compromise and create an incident ticket following NIST 800-61 framework.',
    duration: '1 hour',
    difficulty: 'Intermediate',
    tools: ['Wireshark', 'PCAP', 'NIST 800-61'],
    deliverable: 'Completed incident ticket with IOCs, timeline, and recommended actions',
    status: 'locked'
  }
  // Add more labs as needed
};

