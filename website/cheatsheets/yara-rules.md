# YARA Rule Syntax Cheat Sheet

## Basic Rule Structure

```yara
rule RuleName
{
    meta:
        description = "Rule description"
        author = "Your Name"
        date = "2024-01-15"
        reference = "https://example.com"
    
    strings:
        $string1 = "malicious string"
        $string2 = /regex pattern/
        $hex1 = { E2 34 A1 C8 23 FB }
    
    condition:
        $string1 or $string2
}
```

## Meta Section

```yara
meta:
    description = "Description of the rule"
    author = "Analyst Name"
    date = "2024-01-15"
    version = "1.0"
    reference = "https://example.com/reference"
    hash = "abc123def456"
    malware_family = "Trojan"
    severity = "High"
```

## String Definitions

### Text Strings

```yara
strings:
    $text1 = "Hello World"              # Exact match
    $text2 = "Hello World" nocase       # Case-insensitive
    $text3 = "Hello World" ascii        # ASCII only
    $text4 = "Hello World" wide         # Unicode (UTF-16)
    $text5 = "Hello World" fullword     # Whole word only
```

### Regular Expressions

```yara
strings:
    $regex1 = /malicious.*pattern/      # Basic regex
    $regex2 = /[0-9]{4,}/              # 4+ digits
    $regex3 = /https?:\/\/[^\s]+/      # URLs
    $regex4 = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}/  # Email
```

### Hex Strings

```yara
strings:
    $hex1 = { E2 34 A1 C8 }            # Exact hex
    $hex2 = { E2 34 ?? C8 }            # Wildcard (??)
    $hex3 = { E2 34 [2-4] C8 }         # Range
    $hex4 = { E2 34 ( A1 | B2 ) C8 }  # Alternatives
```

### String Modifiers

| Modifier | Description |
|----------|-------------|
| `nocase` | Case-insensitive |
| `ascii` | ASCII encoding |
| `wide` | Unicode (UTF-16) |
| `fullword` | Whole word match |
| `xor` | XOR obfuscation |
| `base64` | Base64 encoding |

## Conditions

### Basic Conditions

```yara
condition:
    $string1                    # String must be present
    $string1 and $string2       # Both strings required
    $string1 or $string2        # Either string
    not $string1                # String must NOT be present
    $string1 and not $string2    # String1 present, string2 not
```

### Counting Strings

```yara
condition:
    # of them > 2               # More than 2 strings
    # of them < 5               # Less than 5 strings
    # of ($string*) > 2         # More than 2 strings starting with $string
    2 of them                   # Exactly 2 strings
    2 of ($string1, $string2)   # 2 of specific strings
```

### File Properties

```yara
condition:
    filesize < 100KB            # File size less than 100KB
    filesize > 1MB              # File size greater than 1MB
    entrypoint == 0x1000        # Entry point at specific address
    uint16(0) == 0x5A4D        # MZ header (PE file)
```

### String Positions

```yara
condition:
    $string1 at 0               # String at offset 0
    $string1 at entrypoint       # String at entry point
    $string1 in (0..100)         # String in first 100 bytes
    $string1 and $string2 and ($string1 < $string2)  # String1 before string2
```

## Common Rule Patterns

### PE File Detection

```yara
rule PE_File
{
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        uint32(uint32(0x3C)) == 0x00004550  // PE header
}
```

### Malware Family Detection

```yara
rule Trojan_Example
{
    meta:
        description = "Detects Example Trojan"
        author = "Analyst"
        date = "2024-01-15"
    
    strings:
        $s1 = "C2_SERVER" fullword
        $s2 = "MALICIOUS_PAYLOAD" fullword
        $s3 = { E2 34 A1 C8 23 FB }
        $s4 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
    
    condition:
        2 of them
}
```

### Phishing Document Detection

```yara
rule Phishing_Document
{
    meta:
        description = "Detects phishing documents"
    
    strings:
        $s1 = "verify your account" nocase
        $s2 = "click here" nocase
        $s3 = "urgent action required" nocase
        $s4 = /https?:\/\/[^\s]+(login|verify|account)/i
    
    condition:
        3 of them
}
```

### PowerShell Script Detection

```yara
rule PowerShell_Suspicious
{
    meta:
        description = "Detects suspicious PowerShell scripts"
    
    strings:
        $s1 = "DownloadString" nocase
        $s2 = "Invoke-Expression" nocase
        $s3 = "Base64" nocase
        $s4 = "Hidden" nocase
        $s5 = /powershell.*-enc/i
    
    condition:
        3 of them
}
```

### Obfuscated Code Detection

```yara
rule Obfuscated_Code
{
    meta:
        description = "Detects obfuscated code patterns"
    
    strings:
        $s1 = "eval("
        $s2 = "unescape("
        $s3 = "String.fromCharCode"
        $s4 = /[A-Za-z0-9+/]{100,}={0,2}/  # Base64-like strings
    
    condition:
        2 of them
}
```

## Advanced Features

### Loops and Iterations

```yara
rule Multiple_Strings
{
    strings:
        $a = "string1"
        $b = "string2"
        $c = "string3"
    
    condition:
        for any of them : ( $ at entrypoint )
}
```

### File Type Detection

```yara
rule PDF_File
{
    condition:
        uint32(0) == 0x46445025  // %PDF
}
```

### String Sets

```yara
rule String_Set
{
    strings:
        $a = "string1"
        $b = "string2"
        $c = "string3"
    
    condition:
        all of them  // All strings must be present
        any of them  // Any string present
        2 of them    // At least 2 strings
}
```

## Testing Rules

### Command Line

```bash
# Scan single file
yara rule.yar file.exe

# Scan directory
yara -r rule.yar /path/to/directory

# Show strings
yara -s rule.yar file.exe

# Show metadata
yara -g rule.yar file.exe

# Recursive scan
yara -r rule.yar /path/to/scan
```

### Rule Testing

```bash
# Test rule syntax
yara -w rule.yar  # -w suppresses warnings

# Test with sample files
yara rule.yar test_samples/
```

## Best Practices

1. **Descriptive Names**: Use clear, descriptive rule names
2. **Metadata**: Always include description, author, date
3. **References**: Include reference URLs or CVE numbers
4. **String Selection**: Choose unique, reliable strings
5. **Conditions**: Use specific conditions to reduce false positives
6. **Testing**: Test rules against known good and bad samples
7. **Performance**: Use `fullword` and `nocase` appropriately
8. **Maintenance**: Update rules as malware evolves

## Quick Reference

| Element | Syntax |
|---------|--------|
| Text String | `$s1 = "text"` |
| Regex | `$s1 = /pattern/` |
| Hex | `$s1 = { E2 34 A1 }` |
| Case-insensitive | `nocase` |
| Whole word | `fullword` |
| Count | `2 of them` |
| File size | `filesize < 100KB` |
| Entry point | `entrypoint` |

