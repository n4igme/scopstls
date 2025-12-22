# Nuclei How-To Guide

Nuclei is a fast and customizable vulnerability scanner that uses simple YAML-based templates to send requests and matches responses for vulnerability detection.

## Installation

```bash
# On Ubuntu/Debian
curl -s https://raw.githubusercontent.com/projectdiscovery/nuclei/v2.9.4/install.sh | bash

# Using Go (requires Go 1.19+)
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Using Docker
docker pull projectdiscovery/nuclei:latest
```

## Basic Usage

```bash
# Update templates (important for latest vulnerabilities)
nuclei -update-templates

# Run all templates against a target
nuclei -target https://example.com

# Run only specific templates
nuclei -target https://example.com -t http/cves/2023/CVE-2023-1234.yaml

# Run with multiple targets
nuclei -l targets.txt
```

## Real-World Scenario 1: Comprehensive Web Application Security Assessment

**Situation**: You need to perform a security assessment of an internal web application to identify common vulnerabilities.

**Step-by-Step Process**:

1. **Prepare your target list**:
```bash
# Create targets.txt file
echo "https://app.company.com" > targets.txt
echo "https://staging.company.com" >> targets.txt
echo "https://dev.company.com" >> targets.txt
```

2. **Run specific categories of tests**:
```bash
# Run only high/critical severity templates
nuclei -l targets.txt -severity critical,high -o results_critical.txt

# Run only technology detection templates
nuclei -l targets.txt -tags tech -o tech_detection.txt

# Run only CVE-specific templates
nuclei -l targets.txt -tags cve -o cve_results.txt
```

3. **Customize the scan for better results**:
```bash
# Use custom headers (e.g., for authenticated scans)
nuclei -target https://app.company.com -H "Authorization: Bearer token_here" -H "X-Custom-Header: value"

# Set rate limiting to avoid overwhelming the target
nuclei -target https://app.company.com -rate-limit 100

# Use specific protocols for more thorough scanning
nuclei -target https://app.company.com -tp http,https
```

## Real-World Scenario 2: Mass Vulnerability Scanning of Infrastructure

**Situation**: You need to scan multiple domains/URLs to identify widespread vulnerabilities in your organization's infrastructure.

**Step 1**: Create a comprehensive scan script:
```bash
#!/bin/bash
# mass_scan.sh

# Update templates first
nuclei -update-templates

# Define targets
TARGETS_FILE="domains.txt"
OUTPUT_DIR="nuclei_results"
mkdir -p $OUTPUT_DIR

# Scan with different template sets
echo "Running technology detection..."
nuclei -l $TARGETS_FILE -tags tech -o $OUTPUT_DIR/tech_detection.txt

echo "Running known CVEs..."
nuclei -l $TARGETS_FILE -tags cve -severity critical,high -o $OUTPUT_DIR/critical_cves.txt

echo "Running misconfiguration checks..."
nuclei -l $TARGETS_FILE -tags misconfig -o $OUTPUT_DIR/misconfig.txt

echo "Running all high severity templates..."
nuclei -l $TARGETS_FILE -severity high -o $OUTPUT_DIR/high_severity.txt

echo "Scan completed. Results in $OUTPUT_DIR"
```

**Step 2**: Create custom templates for organization-specific checks:
```yaml
# Custom template: internal_api_keys.yaml
id: internal-api-keys

info:
  name: Internal API Keys Disclosure
  author: yourname
  severity: high
  description: Searches for internal API keys in web application responses
  tags: exposure,token

requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
      - "{{BaseURL}}/api/"
      - "{{BaseURL}}/admin/"
      - "{{BaseURL}}/robots.txt"
    
    matchers:
      - type: regex
        part: body
        regex:
          - "(?i)(api_key|secret_key|access_token|api_token)[a-z0-9_\\-=:\\s\"']{30,100}"
    
    extractors:
      - type: regex
        part: body
        regex:
          - "(?i)(api_key|secret_key|access_token|api_token)[a-z0-9_\\-=:\\s\"']{30,100}"
```

**Step 3**: Run the comprehensive scan:
```bash
chmod +x mass_scan.sh
./mass_scan.sh

# Parse the results
cat nuclei_results/*.txt | grep -v "info" | sort | uniq -c | sort -nr
```

## Advanced Nuclei Techniques

**Creating custom workflows**:
```yaml
# custom_workflow.yaml
id: comprehensive-workflow

info:
  name: Comprehensive Application Assessment
  author: yourname
  severity: info

workflows:
  - template: http/technologies/tech-detect.yaml
    subtemplates:
      - tags: cve
      - tags: vulnerabilities
      - tags: exposures
    matchers:
      - name: apache
        subtemplates:
          - id: apache-version-detect
          - tags: apache
      - name: php
        subtemplates:
          - id: php-version-detect
          - tags: php
```

## Common Template Structure

A typical Nuclei template includes:

```yaml
id: template-id

info:
  name: Template Name
  author: Your Name
  severity: info|low|medium|high|critical
  description: Brief description of what the template detects
  reference: URL to vulnerability details
  tags: comma,separated,tags

requests:
  - method: GET|POST|PUT|etc.
    path:
      - "{{BaseURL}}/endpoint"
    
    headers:
      User-Agent: "Mozilla/5.0..."
    
    body: "request body if needed"
    
    matchers:
      - type: status|word|regex|dsl
        part: body|header
        words:
          - "specific text to match"
    
    extractors:
      - type: regex|kval|xpath
        part: body
        regex:
          - 'pattern to extract'
```

## Tips and Best Practices

1. **Always update templates**: Run `nuclei -update-templates` regularly to ensure you have the latest vulnerability checks
2. **Use rate limiting**: When scanning internal infrastructure, use `-rate-limit` to avoid overwhelming services
3. **Filter by severity**: Focus on high/critical severity findings first with `-severity high,critical`
4. **Create custom templates**: Develop templates for organization-specific vulnerabilities
5. **Use tags effectively**: Leverage tags like `-tags cve,misconfig` to focus your scans
6. **Validate findings**: Not all nuclei findings are exploitable; always validate before reporting
7. **Combine with other tools**: Use nuclei as part of a broader security assessment methodology

## Troubleshooting Common Issues

- **403 Forbidden responses**: Add appropriate headers or authentication tokens to your requests
- **Rate limiting**: Use `-rate-limit` to slow down requests to avoid being blocked
- **False positives**: Validate findings manually and refine templates if needed
- **No results**: Ensure templates are updated and check target accessibility
- **Slow scans**: Limit concurrent requests with `-concurrency` flag for better performance