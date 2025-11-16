# Setup Instructions

This guide will help you set up your lab environment for the SOC Analyst I course.

---

## System Requirements

### Minimum Requirements
- **OS:** Linux (Ubuntu 20.04+ recommended) or macOS
- **RAM:** 8GB minimum, 16GB recommended
- **Storage:** 50GB free space
- **CPU:** 2+ cores

### Recommended Setup
- **Virtual Machine:** VMware, VirtualBox, or Hyper-V
- **OS:** Ubuntu 22.04 LTS
- **RAM:** 16GB+
- **Storage:** 100GB+ SSD

---

## Required Tools

All tools listed below are open-source and free to use.

### Network Analysis
- **Wireshark** - Network protocol analyzer
  ```bash
  sudo apt-get update
  sudo apt-get install wireshark
  ```

### Memory Forensics
- **Volatility Framework** - Memory forensics tool
  ```bash
  pip3 install volatility3
  ```

### Detection Engineering
- **Suricata** - Network IDS/IPS
  ```bash
  sudo apt-get install suricata
  ```

- **YARA** - Malware detection tool
  ```bash
  sudo apt-get install yara
  ```

### File Analysis
- **strings** - Extract strings from binaries (usually pre-installed)
- **file** - File type identification (usually pre-installed)
- **exiftool** - Metadata extraction
  ```bash
  sudo apt-get install libimage-exiftool-perl
  ```

### Disk Forensics
- **SleuthKit** - Digital forensics toolkit
  ```bash
  sudo apt-get install sleuthkit
  ```

- **Autopsy** - GUI for SleuthKit
  ```bash
  sudo apt-get install autopsy
  ```

### Cloud Security
- **AWS CLI** - AWS command-line interface
  ```bash
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip awscliv2.zip
  sudo ./aws/install
  ```

### Reverse Engineering
- **Ghidra** - Software reverse engineering framework
  ```bash
  # Download from: https://ghidra-sre.org/
  # Extract and run: ./ghidraRun
  ```

### Text Processing
- **grep, awk, sed** - Command-line text processing (usually pre-installed)

---

## Lab Environment Setup

### 1. Create Lab Directory Structure

```bash
mkdir -p ~/soc-labs/{modules,labs,data,reports}
cd ~/soc-labs
```

### 2. Download Course Materials

```bash
# Clone or download the course repository
cd ~/soc-labs
# Copy course materials to appropriate directories
```

### 3. Set Up Virtual Environment (Optional)

For Python-based tools and scripts:

```bash
python3 -m venv ~/soc-labs/venv
source ~/soc-labs/venv/bin/activate
pip install --upgrade pip
```

### 4. Configure Tools

#### Wireshark
```bash
# Add your user to the wireshark group
sudo usermod -aG wireshark $USER
# Log out and log back in for changes to take effect
```

#### Suricata
```bash
# Configure Suricata
sudo suricata-update
# Edit configuration file
sudo nano /etc/suricata/suricata.yaml
```

#### Volatility
```bash
# Verify installation
vol.py --help
# Download profiles if needed
```

---

## Sample Data Setup

### Download Synthetic Data

The course includes synthetic data samples in the `data/synthetic/` directory:

- Email headers
- PCAP analysis examples
- Linux auth logs
- CloudTrail logs
- Suricata alerts
- YARA detection output

### Create Test PCAP Files

For labs requiring PCAP files, you can:

1. Use the provided synthetic data
2. Capture your own traffic (in a controlled environment)
3. Use publicly available PCAP files from:
   - [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
   - [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)

---

## OSINT Tools Setup

### Web-Based Tools (No Installation Required)
- **VirusTotal** - https://www.virustotal.com/
- **AbuseIPDB** - https://www.abuseipdb.com/
- **Whois** - https://whois.net/ or use command-line `whois`
- **Shodan** - https://www.shodan.io/ (free account available)

### Command-Line Tools
```bash
# Install whois
sudo apt-get install whois

# Install dig (DNS lookup)
sudo apt-get install dnsutils
```

---

## AWS Setup (For Cloud Security Modules)

### 1. Create AWS Account
- Sign up for AWS Free Tier account
- Access to CloudTrail, GuardDuty, VPC Flow Logs (with limitations)

### 2. Configure AWS CLI
```bash
aws configure
# Enter your AWS Access Key ID
# Enter your AWS Secret Access Key
# Enter default region (e.g., us-east-1)
# Enter default output format (json)
```

### 3. Enable CloudTrail
- Navigate to AWS CloudTrail console
- Create a trail
- Enable logging for all regions

### 4. Enable GuardDuty (Optional)
- Navigate to AWS GuardDuty console
- Enable GuardDuty in your region

---

## Verification Checklist

Use this checklist to verify your setup:

- [ ] Wireshark installed and configured
- [ ] Volatility Framework installed
- [ ] Suricata installed and configured
- [ ] YARA installed
- [ ] SleuthKit installed
- [ ] AWS CLI installed and configured (for cloud modules)
- [ ] Lab directory structure created
- [ ] Course materials downloaded
- [ ] Synthetic data samples available
- [ ] OSINT tools accessible

---

## Troubleshooting

### Wireshark Permission Issues
```bash
sudo chmod +x /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
```

### Volatility Profile Issues
```bash
# Download Windows profiles if needed
# Profiles are available from volatilityfoundation/profiles repository
```

### Suricata Rule Updates
```bash
# Update Suricata rules
sudo suricata-update
# Restart Suricata
sudo systemctl restart suricata
```

### AWS CLI Configuration Issues
```bash
# Verify AWS credentials
aws sts get-caller-identity
# Check AWS CLI version
aws --version
```

---

## Additional Resources

### Learning Resources
- **Wireshark Documentation:** https://www.wireshark.org/docs/
- **Volatility Documentation:** https://volatility3.readthedocs.io/
- **Suricata Documentation:** https://suricata.readthedocs.io/
- **YARA Documentation:** https://yara.readthedocs.io/

### Practice Platforms
- **TryHackMe** - SOC-related rooms
- **CyberDefenders** - Blue team challenges
- **Blue Team Labs Online** - SOC analyst training

---

## Next Steps

1. Complete the setup verification checklist
2. Review the course README
3. Start with Module 1: Phishing Attack
4. Complete labs as you progress through each module

---

**Need Help?** Review the course documentation or reach out to the course community for support.

