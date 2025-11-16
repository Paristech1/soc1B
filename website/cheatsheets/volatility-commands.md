# Volatility Framework Commands Cheat Sheet

## Installation and Setup

```bash
# Install Volatility 3
pip3 install volatility3

# Check version
volatility3 --version

# List available plugins
volatility3 -f memory.dump windows.info
```

## Memory Image Information

```bash
# Identify memory image
volatility3 -f memory.dump windows.info

# Get image information
volatility3 -f memory.dump windows.info.Info

# Check image format
volatility3 -f memory.dump windows.info.Info
```

## Process Analysis

### Process Listing

```bash
# List all processes
volatility3 -f memory.dump windows.pslist

# List processes with command line
volatility3 -f memory.dump windows.cmdline

# Process tree
volatility3 -f memory.dump windows.pstree

# List hidden processes
volatility3 -f memory.dump windows.psscan

# List processes with DLLs
volatility3 -f memory.dump windows.dlllist
```

### Process Details

```bash
# Get process details
volatility3 -f memory.dump windows.cmdline.CmdLine

# Process environment variables
volatility3 -f memory.dump windows.envars

# Process handles
volatility3 -f memory.dump windows.handles
```

## Network Analysis

### Network Connections

```bash
# List network connections
volatility3 -f memory.dump windows.netscan

# Network connections (alternative)
volatility3 -f memory.dump windows.netstat

# Socket connections
volatility3 -f memory.dump windows.sockets

# Network artifacts
volatility3 -f memory.dump windows.network.Network
```

### Network Artifacts

```bash
# DNS cache
volatility3 -f memory.dump windows.netscan.NetScan

# ARP cache
volatility3 -f memory.dump windows.arp.Arp
```

## File System Analysis

### File Listing

```bash
# List files in memory
volatility3 -f memory.dump windows.filescan

# Dump files from memory
volatility3 -f memory.dump windows.dumpfiles --physaddr 0x12345678

# File system analysis
volatility3 -f memory.dump windows.mftparser
```

### Registry Analysis

```bash
# List registry hives
volatility3 -f memory.dump windows.registry.hivelist

# Registry key values
volatility3 -f memory.dump windows.registry.printkey -o 0x12345678

# Recent registry activity
volatility3 -f memory.dump windows.registry.userassist
```

## Malware Detection

### Suspicious Processes

```bash
# Processes with suspicious names
volatility3 -f memory.dump windows.pslist | grep -i "svchost\|explorer\|winlogon"

# Processes with unusual PIDs
volatility3 -f memory.dump windows.pslist

# Processes with injected code
volatility3 -f memory.dump windows.malfind
```

### Code Injection Detection

```bash
# Detect code injection
volatility3 -f memory.dump windows.malfind

# Detect API hooks
volatility3 -f memory.dump windows.apihooks

# Detect DLL injection
volatility3 -f memory.dump windows.ldrmodules
```

### Rootkit Detection

```bash
# Detect hidden processes
volatility3 -f memory.dump windows.psscan

# Detect SSDT hooks
volatility3 -f memory.dump windows.ssdt

# Detect driver modules
volatility3 -f memory.dump windows.modules
```

## Credential Extraction

### Password Extraction

```bash
# Extract passwords from memory
volatility3 -f memory.dump windows.hashdump

# Extract LSA secrets
volatility3 -f memory.dump windows.lsadump

# Extract cached credentials
volatility3 -f memory.dump windows.cachedump
```

### Authentication Artifacts

```bash
# Kerberos tickets
volatility3 -f memory.dump windows.kerberos

# WDigest credentials
volatility3 -f memory.dump windows.wdigest
```

## Timeline Analysis

```bash
# Create timeline
volatility3 -f memory.dump windows.timeline

# Timeline with specific time range
volatility3 -f memory.dump windows.timeline --start 2024-01-15 10:00:00
```

## Common Investigation Workflow

### 1. Initial Analysis

```bash
# Get image info
volatility3 -f memory.dump windows.info

# List processes
volatility3 -f memory.dump windows.pslist

# List network connections
volatility3 -f memory.dump windows.netscan
```

### 2. Malware Detection

```bash
# Detect code injection
volatility3 -f memory.dump windows.malfind

# Check for suspicious processes
volatility3 -f memory.dump windows.pslist

# Check network connections
volatility3 -f memory.dump windows.netscan
```

### 3. Deep Dive

```bash
# Process details
volatility3 -f memory.dump windows.cmdline

# DLL analysis
volatility3 -f memory.dump windows.dlllist

# Registry analysis
volatility3 -f memory.dump windows.registry.printkey
```

## Quick Reference

| Task | Command |
|------|---------|
| List processes | `windows.pslist` |
| Process tree | `windows.pstree` |
| Network connections | `windows.netscan` |
| Code injection | `windows.malfind` |
| Registry | `windows.registry.printkey` |
| File listing | `windows.filescan` |
| Hash dump | `windows.hashdump` |
| Timeline | `windows.timeline` |

## Common Red Flags

- ✅ **Suspicious process names**: Processes masquerading as system processes
- ✅ **Unusual network connections**: Connections to external IPs
- ✅ **Code injection**: Malfind detects injected code
- ✅ **Hidden processes**: Processes in psscan but not pslist
- ✅ **Suspicious DLLs**: DLLs loaded in unusual locations
- ✅ **Registry modifications**: Unusual registry keys
- ✅ **Credential dumping**: Hashdump or lsadump activity

