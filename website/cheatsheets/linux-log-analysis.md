# Linux Log Analysis Commands Cheat Sheet

## Authentication Logs (`/var/log/auth.log`)

### Failed Login Attempts

```bash
# Count failed login attempts
grep "Failed password" /var/log/auth.log | wc -l

# Show failed login attempts with usernames
grep "Failed password" /var/log/auth.log | awk '{print $9, $11}' | sort | uniq -c

# Failed SSH login attempts
grep "sshd.*Failed password" /var/log/auth.log

# Failed login attempts by IP
grep "Failed password" /var/log/auth.log | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -rn

# Recent failed logins (last hour)
grep "Failed password" /var/log/auth.log | grep "$(date +'%b %d %H')"
```

### Successful Logins

```bash
# Successful SSH logins
grep "sshd.*Accepted" /var/log/auth.log

# Successful logins with IP addresses
grep "Accepted" /var/log/auth.log | awk '{print $1, $2, $3, $9, $11}'

# Last successful login for a user
grep "Accepted.*username" /var/log/auth.log | tail -1

# All successful logins today
grep "Accepted" /var/log/auth.log | grep "$(date +'%b %d')"
```

### Privilege Escalation

```bash
# sudo usage
grep "sudo" /var/log/auth.log

# Successful sudo commands
grep "sudo.*COMMAND" /var/log/auth.log

# Failed sudo attempts
grep "sudo.*authentication failure" /var/log/auth.log

# su command usage
grep "su:" /var/log/auth.log

# Failed su attempts
grep "su.*FAILED" /var/log/auth.log
```

### User Account Changes

```bash
# User account creation
grep "useradd" /var/log/auth.log

# User account deletion
grep "userdel" /var/log/auth.log

# Password changes
grep "password changed" /var/log/auth.log

# Group changes
grep "groupadd\|groupdel" /var/log/auth.log
```

## System Logs (`journalctl`)

### Basic Queries

```bash
# View all logs
journalctl

# View logs for specific service
journalctl -u ssh
journalctl -u apache2
journalctl -u nginx

# View logs since boot
journalctl -b

# View logs for specific time range
journalctl --since "2024-01-15 10:00:00" --until "2024-01-15 11:00:00"

# View logs for today
journalctl --since today

# View logs for last hour
journalctl --since "1 hour ago"
```

### Filtering and Searching

```bash
# Search for specific keyword
journalctl -g "failed"
journalctl -g "error"
journalctl -g "authentication"

# Filter by priority
journalctl -p err  # Errors only
journalctl -p warning  # Warnings and above
journalctl -p info  # Info and above

# Filter by user
journalctl _UID=1000

# Filter by process
journalctl _PID=1234

# Follow logs in real-time
journalctl -f

# Show last N entries
journalctl -n 100
```

### SSH Logs

```bash
# All SSH-related logs
journalctl -u ssh

# Failed SSH connections
journalctl -u ssh | grep "Failed"

# Successful SSH logins
journalctl -u ssh | grep "Accepted"

# SSH connection attempts from specific IP
journalctl -u ssh | grep "192.168.1.100"
```

## File System Forensics

### File Access Monitoring

```bash
# Find recently modified files
find / -mtime -1  # Modified in last 24 hours
find / -mmin -60  # Modified in last 60 minutes

# Find recently accessed files
find / -atime -1  # Accessed in last 24 hours

# Find files created recently
find / -ctime -1  # Created in last 24 hours

# Find large files
find / -size +100M  # Files larger than 100MB

# Find executable files
find / -type f -perm +111  # Executable files
```

### Suspicious File Locations

```bash
# Check /tmp directory
ls -la /tmp
find /tmp -type f -mtime -1

# Check /var/tmp
ls -la /var/tmp

# Check home directories for suspicious files
find /home -name "*.exe" -o -name "*.bat" -o -name "*.sh"

# Check for hidden files
find / -name ".*" -type f -mtime -1

# Check for files with no extension
find /home -type f ! -name "*.*"
```

### Process Analysis

```bash
# Running processes
ps aux
ps -ef

# Process tree
pstree
pstree -p  # With PIDs

# Processes by user
ps aux | grep username

# Processes listening on network
netstat -tulpn
ss -tulpn
lsof -i

# Processes with network connections
lsof -i -P -n
```

### Network Connections

```bash
# Active network connections
netstat -antp
ss -antp

# Connections to specific IP
netstat -an | grep "192.168.1.100"

# Listening ports
netstat -tulpn | grep LISTEN
ss -tulpn | grep LISTEN

# Established connections
netstat -an | grep ESTABLISHED
```

## Cron Jobs and Scheduled Tasks

```bash
# User cron jobs
crontab -l
crontab -l -u username

# System cron jobs
ls -la /etc/cron.d/
ls -la /etc/cron.hourly/
ls -la /etc/cron.daily/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# Check cron logs
grep CRON /var/log/syslog
journalctl -u cron
```

## System Information

```bash
# System uptime
uptime

# Last logged in users
last
lastlog

# Currently logged in users
who
w

# User login history
last -n 20
last username

# Failed login attempts
lastb
lastb username
```

## File Integrity and Hashes

```bash
# Calculate file hash (MD5)
md5sum filename

# Calculate file hash (SHA256)
sha256sum filename

# Verify file integrity
md5sum -c checksums.md5

# Find files with specific hash
find / -type f -exec md5sum {} \; | grep "abc123def456"
```

## Quick Investigation Workflow

```bash
# 1. Check recent authentication failures
grep "Failed password" /var/log/auth.log | tail -20

# 2. Check successful logins
grep "Accepted" /var/log/auth.log | tail -20

# 3. Check for privilege escalation
grep "sudo" /var/log/auth.log | tail -20

# 4. Check running processes
ps aux | grep -v "\["

# 5. Check network connections
netstat -antp | grep ESTABLISHED

# 6. Check recently modified files
find /home -type f -mtime -1

# 7. Check cron jobs
crontab -l
ls -la /etc/cron.*/
```

## Common Red Flags

- ✅ **Multiple failed logins** from same IP
- ✅ **Successful login** after many failures (brute force)
- ✅ **Sudo usage** by non-admin users
- ✅ **Files in /tmp** with recent timestamps
- ✅ **Suspicious cron jobs** (downloading, executing scripts)
- ✅ **Unusual network connections** to external IPs
- ✅ **Processes** with suspicious names or paths
- ✅ **Files with no extension** in home directories

