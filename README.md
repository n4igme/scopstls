# SecOps Toolkits (scopstls)

A curated directory of security tools for Blue Team, Red Team, and general cybersecurity operations. Searchable, categorized, and maintained.

## Quick Start

Open `index.html` in any browser. No build step, no dependencies.

## Repository Structure

```
scopstls/
├── index.html                 # Main application (single-page tool directory)
├── docs/howto-guides/         # Practical tutorials
│   ├── YARA-HowTo.md
│   ├── Nuclei-HowTo.md
│   ├── Frida-HowTo.md
│   ├── Pwntools-HowTo.md
│   └── BurpExtender-HowTo.md
├── README.md
└── LICENSE (MIT)
```

## Categories

### 🛡️ Blue Team (Defensive Security)
- **Threat Intelligence** — VirusTotal, Hybrid Analysis, CAPEv2, abuse.ch, AlienVault OTX, Shodan, Censys
- **Network Security** — Wireshark, Tcpdump, Snort, Suricata, Zeek, OSSEC, NetworkMiner
- **Endpoint Security** — Elastic Security, Splunk, OSQuery, Sysmon
- **Vulnerability Management** — Nessus, Nexpose, Qualys, OpenVAS, Retire.js, Snyk, AuditJS
- **Incident Response** — Timesketch, OSDFCon

### ⚔️ Red Team (Offensive Security)
- **Web Application Testing** — Burp Suite, OWASP ZAP, Nikto, Nuclei, SQLMap, WPScan, Dalfox, Katana, Smuggler
- **Cloud Security Testing** — Prowler, Pacu
- **Network & Infrastructure** — Nmap, Masscan, Hydra, John the Ripper, Hashcat, Aircrack-ng
- **Exploitation & Post-Exploitation** — Metasploit, Empire, Impacket, Certify

### 🔐 General Security
- **Digital Forensics** — Sleuth Kit, Autopsy, Volatility 3, FileSec
- **Cryptography & Certificates** — SSL Labs, crt.sh, OpenSSL, Keybase
- **DevSecOps & Infrastructure** — Trivy, Grype, secureCodeBox, SAST Scan, Cartography
- **Cloud Security** — BLESS, Repokid, PacBot

## Features

- **77 curated tools** with concise descriptions and tags
- **Left sidebar navigation** with category/subcategory structure
- **Search** by name, description, or tag
- **Color-coded sections** — Blue (defensive), Red (offensive), Purple (general)
- **Deprecated tool indicators** — Archived/unmaintained tools visually flagged
- **How-To Guides** linked directly from sidebar navigation
- **Responsive design** for desktop and mobile
- **Dark theme** optimized for security practitioners
- **Back-to-top button** for quick navigation

## How-To Guides

Practical tutorials with installation, examples, and workflows:

- [YARA](./docs/howto-guides/YARA-HowTo.md) — Pattern matching for malware detection
- [Nuclei](./docs/howto-guides/Nuclei-HowTo.md) — Template-based vulnerability scanning
- [Frida](./docs/howto-guides/Frida-HowTo.md) — Dynamic instrumentation and hooking
- [Pwntools](./docs/howto-guides/Pwntools-HowTo.md) — Binary exploitation framework
- [Burp Extender](./docs/howto-guides/BurpExtender-HowTo.md) — Extending Burp Suite

## Contributing

1. Fork the repository
2. Create a branch (`git checkout -b feature/new-tool`)
3. Add tools using this format in `index.html`:

```html
<div class="tool-card">
    <h5>Tool Name</h5>
    <a href="https://example.com">Visit Tool</a>
    <div class="tool-description">2-3 sentence description of what the tool does and why it's useful.</div>
    <div class="tool-tags">
        <span class="tool-tag">Tag1</span>
        <span class="tool-tag">Tag2</span>
    </div>
</div>
```

4. Commit and open a Pull Request

### Guidelines
- Descriptions: 2-3 sentences max
- Tags: 2-4 per tool, use consistent terminology
- Verify the tool link is active before submitting
- Place the tool in the appropriate category section

## License

[MIT](LICENSE)
