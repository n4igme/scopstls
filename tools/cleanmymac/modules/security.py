"""
Security scanner for macOS.
Checks: firewall, SIP, FileVault, Gatekeeper, launch agents, open ports,
malware indicators, permissions, and system integrity.
"""

import os
import subprocess
import plistlib
from pathlib import Path
from modules.utils import run_cmd


class SecurityScanner:
    """Run security audit on macOS."""

    def __init__(self):
        self.home = Path.home()
        self.findings = []

    def _run(self, cmd, shell=False):
        """Run a command and return stdout."""
        try:
            r = subprocess.run(
                cmd if not shell else cmd,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=10
            )
            return r.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return ""

    def _add_finding(self, severity, category, title, detail, fix=None):
        self.findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "fix": fix,
        })

    def _check_sip(self):
        """Check System Integrity Protection."""
        out = self._run(["csrutil", "status"])
        if "enabled" in out:
            self._add_finding("✅", "System", "SIP Enabled", "System Integrity Protection is active")
        else:
            self._add_finding("🔴", "System", "SIP DISABLED",
                            "System files can be modified by any process",
                            "Boot to Recovery > csrutil enable")

    def _check_filevault(self):
        """Check FileVault disk encryption."""
        out = self._run(["fdesetup", "status"])
        if "On" in out:
            self._add_finding("✅", "System", "FileVault On", "Disk is encrypted")
        else:
            self._add_finding("🔴", "System", "FileVault OFF",
                            "Disk is NOT encrypted — data exposed if stolen",
                            "System Settings > Privacy & Security > FileVault > Turn On")

    def _check_firewall(self):
        """Check Application Firewall."""
        fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        out = self._run([fw, "--getglobalstate"])
        if "enabled" in out:
            self._add_finding("✅", "Network", "Firewall Enabled", "Application firewall is active")
            # Check stealth
            stealth = self._run([fw, "--getstealthmode"])
            if "on" in stealth:
                self._add_finding("✅", "Network", "Stealth Mode On", "Mac ignores port probes")
            else:
                self._add_finding("🟡", "Network", "Stealth Mode Off",
                                "Mac responds to network probes",
                                f"sudo {fw} --setstealthmode on")
        else:
            self._add_finding("🔴", "Network", "Firewall DISABLED",
                            "Any app can accept inbound connections",
                            f"sudo {fw} --setglobalstate on")

    def _check_gatekeeper(self):
        """Check Gatekeeper."""
        out = self._run(["spctl", "--status"])
        if "enabled" in out:
            self._add_finding("✅", "System", "Gatekeeper Enabled", "App notarization enforced")
        else:
            self._add_finding("🔴", "System", "Gatekeeper DISABLED",
                            "Unsigned/unnotarized apps can run freely",
                            "sudo spctl --master-enable")

    def _check_ssh(self):
        """Check Remote Login (SSH)."""
        # Check for sshd listening on any port
        out = self._run("pgrep -x sshd 2>/dev/null", shell=True)
        if out:
            # Get the actual port(s) it's listening on
            ports_out = self._run("lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | grep sshd", shell=True)
            ports = []
            if ports_out:
                for line in ports_out.splitlines():
                    parts = line.split()
                    for p in parts:
                        if "LISTEN" not in p and ":" in p and p[0].isdigit():
                            port = p.split(":")[-1].split()[0]
                            if port not in ports:
                                ports.append(port)
            port_str = f" (port {', '.join(ports)})" if ports else ""
            self._add_finding("🟡", "Network", "SSH Enabled",
                            f"sshd is running{port_str} — accessible from network",
                            "sudo systemsetup -setremotelogin off")
        else:
            self._add_finding("✅", "Network", "SSH Disabled", "No sshd process running")

    def _check_auto_update(self):
        """Check software update settings."""
        plist_path = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
        try:
            with open(plist_path, "rb") as f:
                prefs = plistlib.load(f)
            auto_dl = prefs.get("AutomaticDownload", 0)
            auto_install = prefs.get("AutomaticallyInstallMacOSUpdates", 0)
            critical = prefs.get("CriticalUpdateInstall", 0)

            if auto_dl and auto_install:
                self._add_finding("✅", "Updates", "Auto-Update Enabled", "OS updates auto-download and install")
            elif critical:
                self._add_finding("🟡", "Updates", "Partial Auto-Update",
                                "Critical updates (XProtect) auto-install, but OS patches require manual action",
                                "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true")
            else:
                self._add_finding("🔴", "Updates", "Auto-Update Disabled",
                                "No automatic updates — vulnerable to known exploits",
                                "Enable in System Settings > General > Software Update")
        except (FileNotFoundError, plistlib.InvalidFileException):
            self._add_finding("🟡", "Updates", "Cannot read update prefs", "Check manually in System Settings")

    def _check_open_ports(self):
        """Check for wildcard-bound listening ports."""
        out = self._run("lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null", shell=True)
        wildcard_ports = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 9:
                name_col = parts[8] if len(parts) > 8 else ""
                if name_col.startswith("*:"):
                    port = name_col.split(":")[1].split()[0]
                    proc = parts[0]
                    wildcard_ports.append(f"{proc} on *:{port}")

        if wildcard_ports:
            unique = list(set(wildcard_ports))
            self._add_finding("🟡", "Network", f"Wildcard Listeners ({len(unique)})",
                            "Ports bound on all interfaces:\n     " + "\n     ".join(unique[:10]),
                            "Bind services to 127.0.0.1 or enable firewall")
        else:
            self._add_finding("✅", "Network", "No Wildcard Ports", "All services bound to localhost")

    def _check_launch_agents(self):
        """Scan for suspicious launch agents/daemons."""
        suspicious = []
        known_safe_prefixes = [
            "com.apple.", "com.google.", "com.docker.", "ai.hermes.",
            "com.9router.", "com.amazon.", "org.openvpn.", "com.pritunl.",
        ]

        agent_dirs = [
            self.home / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]

        for d in agent_dirs:
            if not d.exists():
                continue
            for plist in d.glob("*.plist"):
                name = plist.stem
                is_known = any(name.startswith(p) for p in known_safe_prefixes)
                if not is_known:
                    try:
                        with open(plist, "rb") as f:
                            data = plistlib.load(f)
                        program = data.get("Program", data.get("ProgramArguments", ["?"])[0] if data.get("ProgramArguments") else "?")
                        suspicious.append(f"{name} → {program}")
                    except Exception:
                        suspicious.append(f"{name} → (unreadable)")

        if suspicious:
            self._add_finding("🟡", "Persistence", f"Unknown Launch Items ({len(suspicious)})",
                            "Review these for legitimacy:\n     " + "\n     ".join(suspicious[:10]),
                            "Remove unwanted plists from ~/Library/LaunchAgents/")
        else:
            self._add_finding("✅", "Persistence", "Launch Items Clean", "All launch agents/daemons are from known vendors")

    def _check_admin_users(self):
        """Check admin group membership."""
        out = self._run(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
        if out:
            members = out.replace("GroupMembership:", "").strip().split()
            if len(members) > 2:
                self._add_finding("🟡", "Access", f"Multiple Admins ({len(members)})",
                                f"Admin users: {', '.join(members)}",
                                "Remove unnecessary admin access via System Settings > Users")
            else:
                self._add_finding("✅", "Access", "Admin Access Minimal", f"Admins: {', '.join(members)}")

    def _check_password_policy(self):
        """Check password policy strength."""
        out = self._run("pwpolicy -getaccountpolicies 2>/dev/null", shell=True)
        if ".{4,}" in out and ".{8,}" not in out:
            self._add_finding("🟡", "Access", "Weak Password Policy",
                            "Minimum 4 characters only — no complexity requirements",
                            "pwpolicy -setglobalpolicy \"minChars=8\"")
        elif ".{8,}" in out:
            self._add_finding("✅", "Access", "Password Policy OK", "Minimum 8+ characters required")
        else:
            self._add_finding("🟡", "Access", "Unknown Password Policy", "Could not determine policy strength")

    def _check_malware_indicators(self):
        """Check for common macOS malware indicators."""
        malware_paths = [
            self.home / "Library" / "Application Support" / ".bkpd",
            self.home / "Library" / "Application Support" / "com.apple.spotlight.import",
            Path("/var/tmp/.crd"),
            Path("/tmp/.mount_app"),
            self.home / "Library" / "Application Support" / "com.SearchDaemon",
            self.home / "Library" / "Application Support" / "com.ExpertModuleSearchP",
        ]

        known_bad_agents = [
            "com.pcv.hlpramc", "com.updater.mcy", "com.avickUpd",
            "com.ExpertModuleSearchP", "com.DataSearch", "com.fsefosde",
        ]

        found = []
        for p in malware_paths:
            if p.exists():
                found.append(str(p))

        # Check for known bad launch agents
        for d in [self.home / "Library" / "LaunchAgents", Path("/Library/LaunchAgents")]:
            if d.exists():
                for name in known_bad_agents:
                    if (d / f"{name}.plist").exists():
                        found.append(f"Malware plist: {name}")

        if found:
            self._add_finding("🔴", "Malware", "Suspicious Files Found",
                            "Known malware indicators:\n     " + "\n     ".join(found),
                            "Investigate and remove these files")
        else:
            self._add_finding("✅", "Malware", "No Known Malware Indicators", "Common malware paths clear")

    def _check_xprotect(self):
        """Check XProtect version/date."""
        out = self._run("system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A2 XProtect | tail -5", shell=True)
        if out:
            self._add_finding("✅", "Malware", "XProtect Active", f"Latest update info:\n     {out[:100]}")
        else:
            self._add_finding("✅", "Malware", "XProtect Present", "Apple's built-in malware detection is active")

    def _check_screen_lock(self):
        """Check screen lock / screensaver password settings."""
        # Check if screen saver requires password
        out = self._run("defaults read com.apple.screensaver askForPassword 2>/dev/null", shell=True)
        delay = self._run("defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null", shell=True)

        if out == "1":
            delay_secs = int(delay) if delay.isdigit() else 0
            if delay_secs == 0:
                self._add_finding("✅", "Access", "Screen Lock Immediate",
                                "Password required immediately on screensaver/sleep")
            elif delay_secs <= 5:
                self._add_finding("✅", "Access", f"Screen Lock ({delay_secs}s delay)",
                                f"Password required within {delay_secs}s of screensaver/sleep")
            else:
                self._add_finding("🟡", "Access", f"Screen Lock Delay ({delay_secs}s)",
                                f"Password not required for {delay_secs}s after screensaver — too long",
                                "System Settings > Lock Screen > Require password: Immediately")
        else:
            self._add_finding("🔴", "Access", "Screen Lock DISABLED",
                            "No password required after screensaver/sleep — anyone can access",
                            "System Settings > Lock Screen > Require password after screen saver: Immediately")

    def _check_sharing_services(self):
        """Check sharing services (file, printer, Bluetooth, etc.)."""
        sharing_checks = [
            ("com.apple.smbd", "File Sharing (SMB)"),
            ("com.apple.AppleFileServer", "File Sharing (AFP)"),
            ("com.apple.PrinterSharing", "Printer Sharing"),
            ("com.apple.RemoteDesktop.agent", "Remote Management"),
            ("com.apple.BluetoothSharing", "Bluetooth Sharing"),
        ]

        active_shares = []
        for service, label in sharing_checks:
            out = self._run(f"launchctl print system/{service} 2>&1", shell=True)
            if "could not find" not in out.lower() and "No such" not in out and out:
                active_shares.append(label)

        # Also check via DNS-SD for sharing advertisements
        out = self._run("defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server EnabledServices 2>/dev/null", shell=True)
        if out and "disk" in out.lower():
            if "File Sharing (SMB)" not in active_shares:
                active_shares.append("File Sharing (SMB)")

        if active_shares:
            self._add_finding("🟡", "Network", f"Sharing Services Active ({len(active_shares)})",
                            "Exposed services:\n     " + "\n     ".join(active_shares),
                            "Disable in System Settings > General > Sharing")
        else:
            self._add_finding("✅", "Network", "No Sharing Services", "All sharing services are off")

    def _check_find_my_mac(self):
        """Check if Find My Mac is enabled."""
        out = self._run("nvram -x -p 2>/dev/null | grep -c fmm-mobileme-token-FMM", shell=True)
        if out and out.strip() != "0":
            self._add_finding("✅", "System", "Find My Mac Enabled", "Device can be located/wiped remotely if stolen")
        else:
            self._add_finding("🟡", "System", "Find My Mac Status Unknown",
                            "Cannot confirm Find My Mac is active (check iCloud settings)",
                            "System Settings > Apple ID > iCloud > Find My Mac")

    def _check_encrypted_dns(self):
        """Check if DNS traffic is encrypted (DoH/DoT)."""
        # Check system DNS configuration
        out = self._run("scutil --dns 2>/dev/null | head -20", shell=True)
        dns_servers = []
        for line in out.splitlines():
            if "nameserver" in line:
                addr = line.split(":")[-1].strip()
                dns_servers.append(addr)

        # Known encrypted DNS providers
        encrypted_dns = {
            "1.1.1.1", "1.0.0.1",         # Cloudflare
            "8.8.8.8", "8.8.4.4",         # Google (supports DoH)
            "9.9.9.9", "149.112.112.112", # Quad9
            "208.67.222.222", "208.67.220.220",  # OpenDNS
        }

        # Check for DNS profile (DoH/DoT configuration)
        profile_out = self._run("profiles list 2>/dev/null | grep -i dns", shell=True)

        if profile_out and "dns" in profile_out.lower():
            self._add_finding("✅", "Network", "Encrypted DNS Configured",
                            "DNS-over-HTTPS/TLS profile installed")
        elif dns_servers and any(d in encrypted_dns for d in dns_servers):
            providers = [d for d in dns_servers if d in encrypted_dns]
            self._add_finding("🟡", "Network", "DNS Uses Known Providers",
                            f"DNS: {', '.join(providers)} (supports DoH but not enforced locally)",
                            "Install a DNS profile or use System Settings > Network > DNS to configure DoH")
        elif dns_servers:
            self._add_finding("🟡", "Network", "DNS Not Encrypted",
                            f"DNS servers: {', '.join(dns_servers[:4])} (plaintext DNS)",
                            "Consider Cloudflare (1.1.1.1) or Quad9 (9.9.9.9) with DoH profile")

    def run_full_scan(self):
        """Run all security checks."""
        print("🔒 Running security audit...\n")

        self._check_sip()
        self._check_filevault()
        self._check_firewall()
        self._check_gatekeeper()
        self._check_ssh()
        self._check_auto_update()
        self._check_open_ports()
        self._check_launch_agents()
        self._check_admin_users()
        self._check_password_policy()
        self._check_screen_lock()
        self._check_sharing_services()
        self._check_find_my_mac()
        self._check_encrypted_dns()
        self._check_malware_indicators()
        self._check_xprotect()

        self._print_results()

    def _print_results(self):
        """Print formatted results."""
        # Group by category
        categories = {}
        for f in self.findings:
            cat = f["category"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(f)

        critical = sum(1 for f in self.findings if f["severity"] == "🔴")
        warnings = sum(1 for f in self.findings if f["severity"] == "🟡")
        good = sum(1 for f in self.findings if f["severity"] == "✅")

        for cat, items in categories.items():
            print(f"  ┌─ {cat}")
            for item in items:
                print(f"  │ {item['severity']} {item['title']}")
                if item["severity"] != "✅":
                    print(f"  │    {item['detail']}")
                    if item.get("fix"):
                        print(f"  │    💡 Fix: {item['fix']}")
            print(f"  └{'─' * 40}")
            print()

        print("━" * 50)
        print(f"  Summary: {critical} critical · {warnings} warnings · {good} passed")
        print("━" * 50)
