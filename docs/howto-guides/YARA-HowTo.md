# YARA How-To Guide

YARA is a pattern matching tool used to identify and classify malware samples. It uses rules to create descriptions of malware families based on textual or binary patterns.

## Installation

```bash
# On Ubuntu/Debian
sudo apt-get install yara

# On macOS
brew install yara

# Using pip
pip install yara-python

# From source (latest version)
git clone https://github.com/VirusTotal/yara.git
cd yara
./bootstrap.sh
./configure
make
sudo make install
sudo ldconfig
```

## Basic YARA Rule Structure

```yara
rule rule_name {
    meta:
        description = "Description of what the rule detects"
        author = "Your Name"
        date = "2023-01-01"
        reference = "URL or paper reference"
    strings:
        $identifier1 = "some string"    // Text string
        $identifier2 = {4A 4D ?? 50}    // Hex string with wildcard
        $identifier3 = /regex_pattern/  // Regular expression
    condition:
        $identifier1 and $identifier2   // Condition to trigger the rule
}
```

## Real-World Scenario 1: Detecting Specific Malware Family

**Situation**: You've analyzed a malware sample from the "Gootkit" banking trojan and want to create a YARA rule to detect other samples.

**Step-by-Step Process**:

1. **Analyze the sample** - Use tools like strings, hexdump, or disassemblers to find unique patterns
```bash
strings malware_sample.exe | grep -i gootkit
hexdump -C malware_sample.exe | less
```

2. **Create the YARA rule**:
```yara
rule Gootkit_Banking_Trojan {
    meta:
        description = "Detects Gootkit banking trojan samples"
        author = "Security Analyst"
        date = "2023-06-15"
        family = "Gootkit"
        reference = "Analysis of Gootkit samples in June 2023"
    strings:
        $s1 = "GootKitLog.txt"          // Logging filename
        $s2 = "injects.xml"             // Configuration file
        $s3 = { 47 6F 6F 74 4B 69 74 }  // "GootKit" in hex
        $s4 = "https://panel[.]example[.]com" // C2 panel (obfuscated)
    condition:
        all of ($s*) or $s1
}
```

3. **Test the rule**:
```bash
# Create a test rule file
nano gootkit_rule.yar

# Test against a sample
yara gootkit_rule.yar malware_sample.exe

# Test against a directory
yara gootkit_rule.yar /path/to/samples/
```

## Real-World Scenario 2: Detecting Multiple Malware Families

**Situation**: You need to scan a directory for multiple known malware families to triage samples.

**Step 1**: Create a comprehensive rules file:
```yara
/*
 * Multi-family detection rule set
 * Combines indicators for several malware families
 */
 
rule Trojan_Embedded_Pattern {
    strings:
        $s1 = "cmd.exe /c" wide
        $s2 = "powershell" nocase
        $s3 = "reg add" nocase
    condition:
        all of them
}

rule Ransomware_File_Extensions {
    strings:
        $ext1 = ".encrypted" ascii
        $ext2 = ".locked" ascii
        $ext3 = ".locked" wide
        $note = "README_TO_RESTORE" ascii
    condition:
        any of ($ext*) and $note
}

rule Banking_Trojan_Indicators {
    strings:
        $formgrab = "form_grabbed"
        $keylog = "keylog.txt"
        $inject = "inject_"
    condition:
        2 of them
}
```

**Step 2**: Compile and scan efficiently:
```bash
# Compile rules (faster for multiple scans)
yara -C multi_rules.yar  # Creates .yar compiled file

# Scan directory recursively
yara -r multi_rules.yar /path/to/samples/

# Include additional details
yara -r -s multi_rules.yar /path/to/samples/  # Show strings
```

## Advanced YARA Techniques

**Using PE module for Windows executables**:
```yara
import "pe"

rule Packed_Executable {
    condition:
        pe.number_of_sections > 10 and
        pe.characteristics & pe.IMAGE_FILE_UP_SYSTEM_ONLY
}

rule Has_Debug_Info {
    condition:
        pe.has_debug_info
}
```

## Tips and Best Practices

1. **Use specific identifiers**: Create rules that target unique characteristics of malware families to reduce false positives
2. **Combine string types**: Use text, hex, and regex strings to create robust detection patterns
3. **Test thoroughly**: Always validate your rules against clean and malicious samples to ensure accuracy
4. **Optimize performance**: Use fast strings (those that appear frequently in malware but rarely in goodware) at the beginning of your conditions
5. **Keep rules updated**: Malware evolves, so regularly update your rules to maintain effectiveness
6. **Document everything**: Include detailed metadata in your rules to help with future analysis

## Common YARA Strings Explained

- `wide`: Matches strings with null bytes between characters (UTF-16)
- `nocase`: Case-insensitive matching
- `fullword`: Only matches if the string is surrounded by non-alphanumeric characters
- `xor`: Matches strings that are XOR-encoded (e.g., `$a = "string" xor`)
- `private`: Makes the string private, preventing it from being reported in matches

## Troubleshooting Common Issues

- **False Positives**: Too broad of a pattern. Add more specific conditions or strings.
- **False Negatives**: Pattern is too specific. Consider using wildcards or alternative patterns.
- **Performance Issues**: Rule is too complex. Optimize by using faster matching strings first.