# Suricata Rule Syntax Cheat Sheet

## Basic Rule Structure

```
action protocol source_ip source_port direction destination_ip destination_port (options)
```

### Example Rule

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious HTTP Request"; flow:established,to_server; content:"GET"; http_method; content:"/admin/login.php"; http_uri; sid:1000001; rev:1;)
```

## Rule Actions

| Action | Description |
|--------|-------------|
| `alert` | Generate alert and log packet |
| `pass` | Stop processing, don't alert |
| `drop` | Drop packet (IPS mode) |
| `reject` | Drop and send TCP RST or ICMP unreachable |
| `reject` | Drop and send TCP RST or ICMP unreachable |

## Protocols

- `tcp` - TCP traffic
- `udp` - UDP traffic
- `http` - HTTP traffic
- `tls` - TLS/SSL traffic
- `dns` - DNS traffic
- `icmp` - ICMP traffic
- `ip` - Any IP traffic

## Network Variables

| Variable | Description |
|----------|-------------|
| `$HOME_NET` | Internal network (defined in suricata.yaml) |
| `$EXTERNAL_NET` | External network (usually !$HOME_NET) |
| `any` | Any IP address |
| `!$HOME_NET` | Not internal network |

## Ports

- `any` - Any port
- `80` - Specific port
- `80:443` - Port range
- `!80` - Not port 80
- `[80,443,8080]` - Multiple ports

## Direction

- `->` - One direction (source to destination)
- `<>` - Bidirectional

## Common Keywords

### Flow Keywords

```
flow:established,to_server  # Established connection to server
flow:established,to_client  # Established connection to client
flow:stateless              # Stateless protocol (UDP, ICMP)
```

### Content Matching

```
content:"string";           # Match exact string
content:"string"; nocase;   # Case-insensitive
content:"string"; fast_pattern;  # Optimize for performance
content:"string"; depth:100;  # Search only first 100 bytes
content:"string"; offset:10;  # Start search at byte 10
```

### HTTP Keywords

```
http_method;                # Match HTTP method
http_uri;                   # Match URI
http_header;                # Match HTTP header
http_cookie;                # Match cookie
http_user_agent;            # Match user agent
http_host;                  # Match Host header
http_raw_uri;               # Match raw URI
http_raw_header;            # Match raw header
http_raw_cookie;            # Match raw cookie
```

### TLS Keywords

```
tls.subject;                # Match TLS certificate subject
tls.issuerdn;               # Match TLS certificate issuer
tls.fingerprint;            # Match TLS fingerprint
tls.sni;                    # Match Server Name Indication
```

### DNS Keywords

```
dns_query;                  # Match DNS query name
dns_query_type;             # Match DNS query type
dns_query_class;            # Match DNS query class
```

## Rule Options

### Message and Metadata

```
msg:"Alert message";        # Alert message
sid:1000001;                # Signature ID (must be unique)
rev:1;                      # Revision number
classtype:trojan-activity;  # Classification type
reference:url,https://example.com;  # Reference URL
```

### Thresholds

```
threshold:type limit, track by_src, count 5, seconds 60;  # Alert after 5 in 60 seconds
```

### Flowbits

```
flowbits:set,flag_name;     # Set flowbit
flowbits:isset,flag_name;   # Check if flowbit is set
flowbits:unset,flag_name;   # Unset flowbit
```

## Common Rule Patterns

### Phishing Detection

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Phishing: Suspicious login page";
    flow:established,to_server;
    content:"login"; http_uri;
    content:"verify"; http_uri;
    content:"account"; http_uri;
    sid:1000001; rev:1;
)
```

### Malware Download

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Malware: Executable download";
    flow:established,to_server;
    content:"GET"; http_method;
    content:".exe"; http_uri;
    sid:1000002; rev:1;
)
```

### Data Exfiltration

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Data Exfiltration: Large outbound transfer";
    flow:established,to_server;
    dsize:>1000000;  # > 1MB
    sid:1000003; rev:1;
)
```

### C2 Communication

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"C2: Beacon pattern detected";
    flow:established,to_server;
    threshold:type limit, track by_src, count 5, seconds 60;
    sid:1000004; rev:1;
)
```

### DNS Tunneling

```
alert dns $HOME_NET any -> any any (
    msg:"DNS Tunneling: Large DNS query";
    dns_query;
    dsize:>512;  # DNS queries should be small
    sid:1000005; rev:1;
)
```

### SSH Brute Force

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"SSH: Brute force attempt";
    flow:to_server,established;
    flags:S,12;  # SYN flag
    threshold:type threshold, track by_src, count 5, seconds 60;
    sid:1000006; rev:1;
)
```

### Suspicious User Agent

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Suspicious: Non-browser user agent";
    flow:established,to_server;
    http_user_agent;
    content:"curl"; nocase;
    sid:1000007; rev:1;
)
```

## Testing Rules

### Test Rule Syntax

```bash
# Test rule file
suricata -T -c suricata.yaml -S custom.rules

# Test with PCAP
suricata -c suricata.yaml -S custom.rules -r test.pcap

# Run in test mode
suricata -c suricata.yaml -S custom.rules -T
```

### Rule Performance

- Use `fast_pattern` for common content matches
- Use `depth` and `offset` to limit search space
- Use `threshold` to reduce alert volume
- Use `flowbits` to track state across multiple packets

## Best Practices

1. **Unique SIDs**: Use range 1000000-1999999 for custom rules
2. **Descriptive Messages**: Clear, actionable alert messages
3. **Proper Classification**: Use appropriate `classtype`
4. **References**: Include reference URLs for context
5. **Testing**: Always test rules before deploying
6. **Tuning**: Adjust thresholds to reduce false positives

## Quick Reference

| Element | Syntax |
|---------|--------|
| Action | `alert`, `drop`, `pass` |
| Protocol | `tcp`, `udp`, `http`, `dns` |
| Source | `$HOME_NET`, `$EXTERNAL_NET`, `any` |
| Direction | `->`, `<>` |
| Content | `content:"string";` |
| HTTP | `http_method;`, `http_uri;` |
| Threshold | `threshold:type limit, track by_src, count 5, seconds 60;` |
| SID | `sid:1000001;` |

