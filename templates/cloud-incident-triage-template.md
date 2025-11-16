# Cloud Incident Triage Template (AWS Focus)

**Purpose:** A structured approach to investigating suspicious activity in the AWS environment.

**INCIDENT ID:** [INCIDENT-YYYY-YYYY]  
**Date:** [YYYY-MM-DD]  
**Analyst:** [Your Name]  
**Cloud Provider:** AWS

---

## Cloud Incident Triage Checklist

| Step | Action | AWS Log Source | Key Event/Indicator | Status | Notes |
|------|--------|----------------|---------------------|--------|-------|
| **1. Initial Alert** | Identify the affected IAM User/Role and the time of the alert | GuardDuty, CloudWatch | GuardDuty Finding ID, `EventTime` | ☐ | |
| | Review GuardDuty finding details | GuardDuty | Finding Type, Severity, Resource Affected | ☐ | |
| | Check CloudWatch metrics for anomalies | CloudWatch | Unusual API call volume, Error rates | ☐ | |
| **2. IAM Credential Check** | Check for unauthorized `CreateAccessKey` or `UpdateAccessKey` calls | CloudTrail | `CreateAccessKey`, `UpdateAccessKey` | ☐ | |
| | Verify access key creation timestamps | CloudTrail | `EventTime`, `UserIdentity` | ☐ | |
| | Check for access keys created from unusual locations | CloudTrail | `SourceIPAddress`, `UserAgent` | ☐ | |
| | Review IAM user access key list | IAM Console | Active access keys, Last used | ☐ | |
| **3. Privilege Escalation** | Check for `AttachUserPolicy` or `CreatePolicyVersion` calls | CloudTrail | `AttachUserPolicy`, `CreatePolicyVersion` | ☐ | |
| | Review policy changes on compromised user | CloudTrail | `AttachUserPolicy`, `PutUserPolicy` | ☐ | |
| | Check for role assumption from unusual locations | CloudTrail | `AssumeRole`, `SourceIPAddress` | ☐ | |
| | Verify IAM user permissions | IAM Console | Attached policies, Inline policies | ☐ | |
| **4. Reconnaissance** | Check for excessive `ListBuckets`, `DescribeInstances`, or `GetCallerIdentity` calls | CloudTrail | High volume of read-only API calls | ☐ | |
| | Identify unusual API call patterns | CloudTrail | `EventName`, `EventTime`, `SourceIPAddress` | ☐ | |
| | Check for enumeration of resources | CloudTrail | `List*`, `Describe*` API calls | ☐ | |
| | Review CloudTrail logs for reconnaissance indicators | CloudTrail | Multiple `List*` calls in short time | ☐ | |
| **5. Data Exfiltration** | Check for high volume of `GetObject` or `PutObject` calls to S3 | S3 Access Logs, CloudTrail | `GetObject`, `PutObject` | ☐ | |
| | Identify S3 bucket access from unusual IPs | S3 Access Logs | `RemoteIP`, `Requester` | ☐ | |
| | Check for large data transfers | CloudTrail, VPC Flow Logs | Data transfer volume, `BytesTransferred` | ☐ | |
| | Review S3 bucket policies for misconfigurations | S3 Console | Bucket policies, ACLs | ☐ | |
| **6. Containment** | Immediately disable the compromised IAM User/Role | IAM Console | `UpdateUser` (Status: Inactive) | ☐ | |
| | Revoke all associated access keys | IAM Console | Delete access keys | ☐ | |
| | Detach all policies from compromised user | IAM Console | Detach policies | ☐ | |
| | Block source IP addresses at Security Groups | EC2 Console | Security Group rules | ☐ | |
| **7. Network Analysis** | Check VPC Flow Logs for connections to known malicious external IPs | VPC Flow Logs | High volume of traffic to external IP | ☐ | |
| | Identify unusual outbound connections | VPC Flow Logs | `dstaddr`, `dstport`, `bytes` | ☐ | |
| | Review Security Group rules for unauthorized access | EC2 Console | Inbound/Outbound rules | ☐ | |
| | Check for data exfiltration patterns | VPC Flow Logs | Large outbound transfers | ☐ | |

---

## Initial Alert Details

| Field | Value |
|-------|-------|
| **Alert Source** | (GuardDuty / CloudWatch / Manual / Other) |
| **Alert ID** | |
| **Alert Time** | |
| **Severity** | (CRITICAL / HIGH / MEDIUM / LOW) |
| **Affected Resource** | |
| **IAM User/Role** | |
| **Region** | |

---

## IAM Investigation

### Compromised IAM User/Role Details

| Field | Value |
|-------|-------|
| **IAM User/Role Name** | |
| **ARN** | |
| **Creation Date** | |
| **Last Activity** | |
| **Access Keys** | |
| **Attached Policies** | |
| **Inline Policies** | |

### Suspicious CloudTrail Events

| Timestamp | Event Name | Source IP | User Agent | Resource | Status |
|-----------|------------|-----------|------------|----------|--------|
| | | | | | |

### Access Key Analysis

| Access Key ID | Created | Last Used | Location | Status |
|---------------|---------|-----------|----------|--------|
| | | | | Active / Inactive / Revoked |

---

## Privilege Escalation Analysis

### Policy Changes

| Timestamp | Event | Policy ARN | Action | Source IP |
|-----------|-------|------------|--------|-----------|
| | | | | |

### Role Assumptions

| Timestamp | Role ARN | Source IP | User Agent | Duration |
|-----------|----------|-----------|------------|----------|
| | | | | |

---

## Reconnaissance Activity

### API Call Patterns

| Timestamp | Event Name | Resource | Source IP | Count |
|-----------|------------|----------|-----------|-------|
| | | | | |

### Enumerated Resources

| Resource Type | Resource Name | Timestamp | Source IP |
|---------------|---------------|-----------|-----------|
| | | | |

---

## Data Exfiltration Analysis

### S3 Access Patterns

| Timestamp | Bucket | Object | Operation | Requester | Bytes | Source IP |
|-----------|--------|--------|-----------|-----------|-------|-----------|
| | | | | | | |

### Data Transfer Summary

| Time Period | Total Bytes | Source | Destination | Protocol |
|-------------|-------------|--------|-------------|----------|
| | | | | |

### Exfiltrated Data

| Bucket | Objects | Estimated Size | Data Type | Status |
|--------|---------|----------------|-----------|--------|
| | | | | Confirmed / Suspected |

---

## Network Analysis

### VPC Flow Logs Analysis

| Timestamp | Source IP | Destination IP | Port | Protocol | Bytes | Action |
|-----------|-----------|----------------|------|----------|-------|--------|
| | | | | | | |

### Suspicious Connections

| Source | Destination | Port | Protocol | Volume | Purpose |
|--------|-------------|------|----------|--------|---------|
| | | | | | C2 / Exfil / Other |

### Security Group Review

| Security Group ID | Rule Type | Protocol | Port | Source/Destination | Status |
|------------------|-----------|----------|------|---------------------|--------|
| | | | | | Authorized / Unauthorized |

---

## Containment Actions

| Action | Timestamp | Performed By | Details |
|--------|-----------|--------------|---------|
| IAM User Disabled | | | |
| Access Keys Revoked | | | |
| Policies Detached | | | |
| Security Group Rules Updated | | | |
| S3 Bucket Access Restricted | | | |
| VPC Route Tables Updated | | | |

---

## Impact Assessment

### Affected Resources

| Resource Type | Resource ID/Name | Region | Status |
|---------------|------------------|--------|--------|
| | | | |

### Data at Risk

| Data Type | Location | Estimated Volume | Status |
|-----------|----------|------------------|--------|
| | | | Confirmed / Suspected / Safe |

### Business Impact

- **Service Disruption:** [Yes / No]
- **Data Breach:** [Confirmed / Suspected / No]
- **Financial Impact:** [Estimated cost]
- **Reputation Impact:** [Description]

---

## Recommended Next Steps

### Immediate Actions

1. [ ]
2. [ ]
3. [ ]

### Long-Term Remediation

1. [ ]
2. [ ]
3. [ ]

### Detection Improvements

1. [ ]
2. [ ]
3. [ ]

---

## Notes

[Additional notes, observations, or findings]

---

**Status:** [OPEN / IN PROGRESS / RESOLVED]  
**Assigned To:** [Analyst Name]  
**Next Review:** [Date/Time]

