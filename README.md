# Security Operations Toolkit Index (scopstls)

A comprehensive collection of security tools for Blue Team, Red Team, and general cybersecurity operations. This repository serves as an index and launching point for various security tools used in defensive and offensive security operations.

## Purpose

This repository aims to provide:
- A centralized index of commonly used security tools
- Quick access to both online and offline security utilities
- Organization of tools by category and use case
- Educational resources for security practitioners
- Searchable directory with tags and descriptions
- Responsive design for all device types
- Clean, modern interface with intuitive navigation

## Categories

### Blue Team (Defensive Security)
Tools and resources focused on defending networks, systems, and data:
- **Threat Intelligence & Intel** - Malware analysis, IoCs, and reconnaissance
- **Network Security** - Traffic analysis, monitoring, and intrusion detection
- **Endpoint Security** - EDR, SIEM, and host monitoring solutions
- **Vulnerability Management** - Scanning and management tools
- **Incident Response** - Forensic analysis and alerting tools
- **DevSecOps** - Infrastructure and development security

### Red Team (Offensive Security)
Tools and resources for penetration testing and offensive operations:
- **Web Application Testing** - Web security, scanning, and proxy tools
- **Network & Infrastructure Testing** - Scanning, enumeration, and password auditing
- **Exploitation & Post-Exploitation** - Exploitation frameworks and C2 tools
- **Cloud Security Testing** - Cloud platform assessment tools

### General Security
Tools applicable to both defensive and offensive operations:
- **Digital Forensics** - Disk, memory, and file analysis tools
- **Cryptography & Certificates** - Encryption and certificate validation
- **DevSecOps & Infrastructure Security** - Container, CI/CD, and infrastructure tools
- **Cloud Security** - Configuration, compliance, and testing tools

## Navigation Structure

The repository features a clean, left-sidebar navigation for improved usability:
- **Home** 🏠 - Return to main page
- **Blue Team** 🛡️ - Defensive security tools
- **TI & Intel** 📊 - Threat intelligence and malware analysis
- **Network Security** 📡 - Network monitoring and analysis tools
- **IR & Forensics** 🔍 - Incident response and forensics tools
- **DevSecOps** 🌐 - Development security tools
- **Red Team** ⚔️ - Offensive security tools
- **Web Pentesting** 🌐 - Web application testing tools
- **Cloud Pentesting** ☁️ - Cloud security testing tools
- **Network Pentesting** 💻 - Network exploitation tools
- **General Security** 🔐 - Cross-functional security tools

## Features

- **Enhanced Navigation**: Left sidebar with clear categorization and subcategories
- **Search Functionality**: Quickly find tools by name, category, or description
- **Rich Tool Descriptions**: Detailed descriptions with practical use cases for each tool
- **Tagging System**: Tools are tagged with relevant keywords for better discoverability
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Smooth Scrolling**: Click navigation links to jump to sections
- **Visual Highlighting**: Current section highlighted in sidebar during scroll
- **Regular Updates**: Tools are periodically reviewed and updated

## Recently Added & Enhanced Tools

### Blue Team Enhancements
- **[Retire.js](https://github.com/RetireJS/retire.js/)** - Comprehensive security scanner for detecting vulnerable JavaScript libraries (Dependency & Code Scanning section)
- **[Snyk](https://snyk.io/)** - Developer-first security platform for finding and fixing vulnerabilities in open-source dependencies (Dependency & Code Scanning section)
- **[AuditJS](https://github.com/sonatype-nexus-community/auditjs)** - npm package vulnerability scanner with Sonatype integration (Dependency & Code Scanning section)
- **[Timesketch](https://github.com/google/timesketch)** - Collaborative forensic timeline analysis platform by Google (Incident Response section)
- **[OSDFCon](https://www.osdfcon.org/)** - Open Source Digital Forensics Conference resources (Incident Response section)
- **[Security Monkey](https://github.com/Netflix/security_monkey)** - Security auditing tool for monitoring cloud accounts for policy changes (Incident Response section)
- **[ThreatIngestor](https://github.com/InQuest/ThreatIngestor)** - Extensible framework for automating threat intelligence collection (Incident Response section)

### Red Team Enhancements
- **[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)** - PowerShell post-exploitation framework for penetration testing (Exploitation & Post-Exploitation section)
- **[Empire](https://github.com/BC-SECURITY/Empire)** - PowerShell and Python 3 post-exploitation agent with command and control capabilities (Exploitation & Post-Exploitation section)
- **[Covenant](https://github.com/cobbr/Covenant)** - .NET command and control framework with web-based interface (Exploitation & Post-Exploitation section)
- **[Certify](https://github.com/GhostPack/Certify)** - .NET tool for Active Directory Certificate Services enumeration and abuse (Exploitation & Post-Exploitation section)
- **[Impacket](https://github.com/fortra/impacket)** - Collection of Python classes for network protocols with extensive command-line tools (Exploitation & Post-Exploitation section)

### General Security Enhancements
- **[MalAPI](https://malapi.io/)** - Malware API providing programmatic access to malware data (Threat Intelligence section)
- **[FileSec](https://filesec.io/)** - File security and analysis resources (Digital Forensics section)

## Our Tools

### EML File Checker
Located in the `/phishing/emlckr.html` directory, this tool allows users to analyze .eml files for:
- Email authentication indicators (SPF, DKIM, DMARC)
- Suspicious URLs and content
- Dangerous file attachments
- Phishing indicators
- Sender spoofing detection

## Contributing

We welcome contributions to improve and expand this security tools index. To contribute:

1. Fork the repository
2. Create a new branch for your changes (`git checkout -b feature/amazing-tool`)
3. Add or update tools in the appropriate category in `index.html`
4. Follow the existing format and ensure links are accurate
5. Add detailed, meaningful descriptions explaining the tool's purpose and capabilities
6. Add relevant tags to help with discoverability
7. Commit your changes (`git commit -m 'Add amazing new security tool'`)
8. Push to the branch (`git push origin feature/amazing-tool`)
9. Open a Pull Request

### Tool Entry Template

When contributing new tools, please follow this standardized format:

```html
<div class="tool-card">
    <h5>Tool Name</h5>
    <a href="URL">Visit Tool</a>
    <div class="tool-description">Comprehensive description of the tool, its features, use cases, and how it benefits security professionals. Explain its purpose, functionality, and practical applications in security operations.</div>
    <div class="tool-tags">
        <span class="tool-tag">Tag1</span>
        <span class="tool-tag">Tag2</span>
        <span class="tool-tag">Tag3</span>
    </div>
</div>
```

### Example:
```html
<div class="tool-card">
    <h5>Example Tool</h5>
    <a href="https://example.com/">Visit Tool</a>
    <div class="tool-description">A powerful security tool that enables security professionals to perform comprehensive security assessments. Example Tool provides advanced capabilities for vulnerability detection, threat analysis, and security monitoring. It integrates with existing security workflows and offers detailed reporting to help organizations understand and remediate security risks. The tool is particularly effective in identifying configuration issues and potential attack vectors.</div>
    <div class="tool-tags">
        <span class="tool-tag">Security Assessment</span>
        <span class="tool-tag">Vulnerability Detection</span>
        <span class="tool-tag">Threat Analysis</span>
    </div>
</div>
```

### Naming Convention for Tags:
- Use descriptive tags that help with search and categorization
- Use consistent terminology (e.g., "Vulnerability Scanner" instead of "Vuln Scanner")
- Include both technical and functional tags when appropriate
- Limit to 2-4 relevant tags per tool
- Use lowercase with hyphens for multi-word terms (e.g., "post-exploitation")

## Development Guidelines

### Repository Structure
- `index.html` - Main security tools index with all categories and tools
- `phishing/emlckr.html` - Our EML file analysis tool
- `README.md` - This documentation file
- `LICENSE` - Project licensing information

### Code Standards
- HTML: Valid semantic markup with proper class naming
- CSS: Use CSS variables for consistent theming (see `:root` definitions)
- JavaScript: Follow existing search and navigation patterns
- Formatting: Consistent indentation and structure

## License

This project is open source and available under the [MIT License](LICENSE).

## Acknowledgments

- Thanks to all contributors who help maintain this comprehensive security tools index
- Special thanks to the security community for developing and sharing these valuable tools
- Inspired by the need for a centralized, well-organized security tool repository
- Appreciation to the developers of all tools listed in this index