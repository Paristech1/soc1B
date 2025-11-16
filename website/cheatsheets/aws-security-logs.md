# AWS Security Logs Reference

## CloudTrail

### Key Event Types

| Event Name | Description | Use Case |
|------------|-------------|----------|
| `AssumeRole` | IAM role assumption | Privilege escalation detection |
| `CreateUser` | New IAM user creation | Unauthorized access |
| `PutUserPolicy` | IAM policy attachment | Policy abuse |
| `CreateAccessKey` | New access key creation | Credential theft |
| `DeleteTrail` | CloudTrail deletion | Log tampering |
| `StopLogging` | CloudTrail logging stopped | Log evasion |
| `CreateBucket` | S3 bucket creation | Data exfiltration setup |
| `PutObject` | S3 object upload | Data exfiltration |
| `GetObject` | S3 object download | Data access |
| `AuthorizeSecurityGroupIngress` | Security group rule added | Network access change |
| `RunInstances` | EC2 instance launch | Resource abuse |

### CloudTrail Log Structure

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAIOSFODNN7EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/john",
    "accountId": "123456789012",
    "userName": "john"
  },
  "eventTime": "2024-01-15T10:30:45Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateUser",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.45",
  "userAgent": "aws-cli/2.0.0",
  "requestParameters": {
    "userName": "attacker"
  },
  "responseElements": {
    "user": {
      "userName": "attacker",
      "userId": "AIDAIOSFODNN7EXAMPLE"
    }
  }
}
```

### CloudTrail Query Examples

```bash
# Find IAM user creation events
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser

# Find events from specific IP
aws cloudtrail lookup-events --lookup-attributes AttributeKey=SourceIPAddress,AttributeValue=203.0.113.45

# Find events by user
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=john

# Find S3 access events
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject

# Find events in time range
aws cloudtrail lookup-events --start-time 2024-01-15T10:00:00Z --end-time 2024-01-15T11:00:00Z
```

### CloudTrail Log Analysis (jq)

```bash
# Extract all event names
cat cloudtrail.json | jq '.Records[].eventName' | sort | uniq -c

# Find failed API calls
cat cloudtrail.json | jq '.Records[] | select(.errorCode != null)'

# Find events from external IPs
cat cloudtrail.json | jq '.Records[] | select(.sourceIPAddress | startswith("203.") or startswith("198."))'

# Find IAM policy changes
cat cloudtrail.json | jq '.Records[] | select(.eventName | contains("Policy"))'

# Find S3 access patterns
cat cloudtrail.json | jq '.Records[] | select(.eventSource == "s3.amazonaws.com")'
```

---

## GuardDuty

### Finding Types

| Finding Type | Description | Severity |
|--------------|-------------|----------|
| `UnauthorizedAPICall` | API call from unusual location | Medium |
| `UnauthorizedAPICall:EC2/ReconEC2` | EC2 reconnaissance activity | High |
| `Recon:IAMUser/InstanceCredentialExfiltration` | Credential theft attempt | Critical |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | CloudTrail logging disabled | High |
| `Backdoor:EC2/DenialOfService.Tcp` | DDoS attack | High |
| `Backdoor:EC2/Spambot` | Spam activity | Medium |
| `CryptoCurrency:EC2/BitcoinTool.B` | Cryptocurrency mining | Medium |
| `Trojan:EC2/DriveBySourceTraffic` | Malicious traffic | High |

### GuardDuty Finding Structure

```json
{
  "schemaVersion": "2.0",
  "accountId": "123456789012",
  "region": "us-east-1",
  "partition": "aws",
  "id": "abc123def456",
  "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/abc123/finding/def456",
  "type": "UnauthorizedAPICall",
  "resource": {
    "resourceType": "AccessKey",
    "accessKeyDetails": {
      "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
      "principalId": "AIDAIOSFODNN7EXAMPLE",
      "userName": "john",
      "userType": "IAMUser"
    }
  },
  "service": {
    "serviceName": "guardduty",
    "detectorId": "abc123",
    "action": {
      "actionType": "AWS_API_CALL",
      "awsApiCallAction": {
        "api": "CreateUser",
        "callerType": "Remote IP",
        "remoteIpDetails": {
          "ipAddressV4": "203.0.113.45",
          "organization": {
            "asn": "12345",
            "asnOrg": "Example ISP"
          },
          "country": {
            "countryName": "United States"
          }
        },
        "serviceName": "iam"
      }
    },
    "eventFirstSeen": "2024-01-15T10:30:45.000Z",
    "eventLastSeen": "2024-01-15T10:35:00.000Z"
  },
  "severity": 7.0,
  "createdAt": "2024-01-15T10:30:45.000Z",
  "updatedAt": "2024-01-15T10:35:00.000Z"
}
```

### GuardDuty Query Examples

```bash
# List all findings
aws guardduty list-findings --detector-id abc123

# Get specific finding
aws guardduty get-findings --detector-id abc123 --finding-ids def456

# Filter by severity
aws guardduty list-findings --detector-id abc123 --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}'

# Filter by finding type
aws guardduty list-findings --detector-id abc123 --finding-criteria '{"Criterion":{"type":{"Eq":["UnauthorizedAPICall"]}}}'
```

---

## VPC Flow Logs

### Flow Log Format

```
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
2 123456789012 eni-abc123 10.0.1.100 203.0.113.45 49152 443 6 10 1024 1609459200 1609459260 ACCEPT OK
```

### Field Descriptions

| Field | Description | Example |
|-------|-------------|---------|
| `version` | Flow log version | 2 |
| `account-id` | AWS account ID | 123456789012 |
| `interface-id` | Network interface ID | eni-abc123 |
| `srcaddr` | Source IP address | 10.0.1.100 |
| `dstaddr` | Destination IP address | 203.0.113.45 |
| `srcport` | Source port | 49152 |
| `dstport` | Destination port | 443 |
| `protocol` | IP protocol number | 6 (TCP) |
| `packets` | Number of packets | 10 |
| `bytes` | Number of bytes | 1024 |
| `start` | Start time (Unix timestamp) | 1609459200 |
| `end` | End time (Unix timestamp) | 1609459260 |
| `action` | ACCEPT or REJECT | ACCEPT |
| `log-status` | Log status | OK |

### VPC Flow Log Analysis

```bash
# Find large data transfers (exfiltration)
awk '$10 > 10000000 {print}' vpc-flow.log  # > 10MB

# Find connections to external IPs
awk '$5 !~ /^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\./ {print}' vpc-flow.log

# Find rejected connections
grep "REJECT" vpc-flow.log

# Find connections to specific port
awk '$7 == 443 {print}' vpc-flow.log

# Count connections by destination
awk '{print $5}' vpc-flow.log | sort | uniq -c | sort -rn

# Find suspicious port combinations
awk '$7 < 1024 && $8 > 49152 {print}' vpc-flow.log  # Low source port, high dest port
```

---

## S3 Access Logs

### S3 Access Log Format

```
79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be mybucket [15/Jan/2024:10:30:45 +0000] 203.0.113.45 - 79a59df900b949e55d96a1e698fbaced ARN "GET /mybucket/myfile.txt HTTP/1.1" 200 - - 1234 1234 - 60 - "-" "S3Console/0.4" -
```

### S3 Access Log Analysis

```bash
# Find all GET requests
grep "GET" s3-access.log

# Find requests from external IPs
grep -v "10\.\|172\.(1[6-9]\|2[0-9]\|3[01])\." s3-access.log

# Find failed requests (4xx, 5xx)
grep -E " (4|5)[0-9]{2} " s3-access.log

# Find large file downloads
awk '$12 > 1000000 {print}' s3-access.log  # > 1MB

# Count requests by IP
awk '{print $4}' s3-access.log | sort | uniq -c | sort -rn
```

---

## Common Investigation Queries

### IAM Abuse Detection

```bash
# Find IAM user creation from external IP
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  | jq '.Events[] | select(.CloudTrailEvent | fromjson | .sourceIPAddress | startswith("203."))'

# Find policy changes
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutUserPolicy
```

### Data Exfiltration Detection

```bash
# Find S3 GetObject from external IPs
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  | jq '.Events[] | select(.CloudTrailEvent | fromjson | .sourceIPAddress | startswith("203."))'

# Find large S3 downloads in VPC Flow Logs
awk '$5 !~ /^10\./ && $10 > 10000000 {print}' vpc-flow.log
```

### Unauthorized Access Detection

```bash
# Find GuardDuty unauthorized API calls
aws guardduty list-findings \
  --detector-id abc123 \
  --finding-criteria '{"Criterion":{"type":{"Eq":["UnauthorizedAPICall"]}}}'
```

---

## Quick Reference

| Log Type | Best For | Key Fields |
|----------|----------|------------|
| CloudTrail | API activity, IAM events | eventName, sourceIPAddress, userIdentity |
| GuardDuty | Threat detection, anomalies | type, severity, resource |
| VPC Flow Logs | Network traffic analysis | srcaddr, dstaddr, bytes, action |
| S3 Access Logs | S3 bucket access | IP, request, response code, bytes |

