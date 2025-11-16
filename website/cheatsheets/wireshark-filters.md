# Wireshark Filters Cheat Sheet

## Display Filters (Analysis)

### Basic Filters

```
# Filter by IP address
ip.addr == 192.168.1.100
ip.src == 192.168.1.100
ip.dst == 192.168.1.100

# Filter by port
tcp.port == 80
udp.port == 53
tcp.dstport == 443
tcp.srcport == 8080

# Filter by protocol
http
https
dns
ftp
ssh
smb
```

### HTTP/HTTPS Filters

```
# HTTP requests
http.request
http.request.method == "GET"
http.request.method == "POST"
http.request.uri contains "login"
http.request.uri contains ".exe"
http.request.uri contains ".php"

# HTTP responses
http.response
http.response.code == 200
http.response.code == 404
http.response.code >= 400

# HTTPS/TLS
tls
ssl
tls.handshake.type == 1  # Client Hello
tls.handshake.type == 2  # Server Hello
```

### DNS Filters

```
# DNS queries
dns
dns.flags.response == 0  # Query only
dns.qry.name contains "malicious"
dns.qry.name == "example.com"

# DNS responses
dns.flags.response == 1  # Response only
dns.resp.name contains "malicious"
dns.a  # A record responses
dns.aaaa  # AAAA record responses
```

### File Transfer Detection

```
# FTP transfers
ftp
ftp-data
ftp.request.command == "RETR"  # File download
ftp.request.command == "STOR"  # File upload

# HTTP file downloads
http.request.uri contains ".exe"
http.request.uri contains ".zip"
http.request.uri contains ".pdf"
http.content_type contains "application/octet-stream"

# Large file transfers (> 1MB)
tcp.len > 1048576
http.content_length > 1048576
```

### C2 and Exfiltration Detection

```
# Suspicious outbound connections
ip.src == 192.168.1.0/24 && ip.dst != 192.168.1.0/24
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst != 192.168.1.0/24

# DNS tunneling (large DNS packets)
dns && frame.len > 512
dns.qry.name.len > 50

# Beacon traffic (regular intervals)
tcp && frame.time_delta > 29 && frame.time_delta < 31

# Data exfiltration patterns
tcp.len > 10000 && ip.dst != 192.168.1.0/24
http.request.method == "POST" && http.content_length > 10000
```

### Phishing and Malware Detection

```
# Suspicious HTTP headers
http.user_agent contains "curl"
http.user_agent contains "wget"
http.user_agent contains "python"

# Malicious file downloads
http.request.uri matches "\.(exe|bat|scr|vbs|js)$"
http.content_type contains "application/x-msdownload"

# Suspicious domains
dns.qry.name matches ".*[0-9]{4,}.*"  # Domains with many numbers
dns.qry.name matches ".*amazon.*security.*"  # Typosquatting patterns
```

### Authentication and Credential Theft

```
# HTTP basic auth
http.authorization
http.authorization contains "Basic"

# FTP credentials
ftp.request.command == "USER"
ftp.request.command == "PASS"

# SMTP authentication
smtp.req.command == "AUTH"
smtp.auth.username
smtp.auth.password
```

### Network Scanning Detection

```
# Port scans (many SYN packets to different ports)
tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport

# ICMP scans
icmp.type == 8  # Echo request
icmp.code == 0

# ARP scans
arp.opcode == 1  # ARP request
```

### DDoS Detection

```
# SYN flood
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 192.168.1.100

# UDP flood
udp && ip.dst == 192.168.1.100

# High packet rate
frame.number > 1000 && frame.time < 1  # 1000+ packets in 1 second
```

### Advanced Filters

```
# Combine multiple conditions
(ip.addr == 192.168.1.100) && (tcp.port == 80 || tcp.port == 443)

# Exclude specific traffic
!(ip.addr == 192.168.1.1)  # Exclude gateway
!(dns)  # Exclude DNS traffic

# Time-based filters
frame.time >= "2024-01-15 10:00:00"
frame.time <= "2024-01-15 11:00:00"

# Packet size filters
frame.len > 1500  # Large packets
frame.len < 100  # Small packets (beacons)
```

## Capture Filters (Live Capture)

```
# Capture only specific IP
host 192.168.1.100

# Capture specific port
port 80

# Capture specific protocol
tcp
udp

# Capture specific network
net 192.168.1.0/24

# Exclude traffic
not host 192.168.1.1
```

## Useful Statistics

### View → Statistics → Protocol Hierarchy
- Shows protocol distribution
- Identifies unusual protocols

### Statistics → Conversations
- Shows top talkers
- Identifies suspicious connections

### Statistics → I/O Graph
- Visualizes traffic patterns
- Identifies anomalies

## Common Analysis Workflows

### Phishing Investigation
1. Filter: `http.request.uri contains "login" || http.request.uri contains "verify"`
2. Follow HTTP stream
3. Check DNS queries for suspicious domains
4. Look for file downloads

### Data Exfiltration
1. Filter: `tcp.len > 10000 && ip.dst != 192.168.1.0/24`
2. Check for large POST requests
3. Analyze file transfer protocols (FTP, SFTP, HTTP)
4. Look for encrypted tunnels

### C2 Detection
1. Filter: `tcp && frame.time_delta > 29 && frame.time_delta < 31`
2. Check for beacon patterns
3. Analyze DNS queries
4. Look for unusual ports

### Malware Analysis
1. Filter: `http.request.uri matches "\.(exe|dll|bat|scr)$"`
2. Follow HTTP stream to download
3. Check file hashes
4. Analyze C2 communications

## Quick Tips

- **Right-click → Follow → TCP Stream**: See full conversation
- **Right-click → Follow → HTTP Stream**: See HTTP request/response
- **Statistics → Endpoints**: See all IPs and ports
- **File → Export Objects → HTTP**: Extract downloaded files
- **View → Time Display Format**: Change time format for analysis

## Keyboard Shortcuts

- `Ctrl+F`: Find packets
- `Ctrl+E`: Export packets
- `Ctrl+Shift+F`: Find in packets
- `Ctrl+Alt+Shift+T`: Time display format
- `Ctrl+→`: Next packet
- `Ctrl+←`: Previous packet

