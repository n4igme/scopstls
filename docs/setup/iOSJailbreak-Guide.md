# AppSec: iOS Jailbreak Guide

# iOS Jailbreak Guide for Penetration Testing

## Environment

- Host: macOS 15.7.7 (Apple Silicon M4)
- Target: iPhone for mobile app security testing
- Purpose: Jailbreak for Frida, SSL bypass, RASP bypass

---

## Identify Your Device

```bash
# Connected via USB:
brew install libimobiledevice
ideviceinfo -k ProductType      # e.g., iPhone10,6 = iPhone X
ideviceinfo -k ProductVersion   # e.g., 17.4.1
ideviceinfo -k HardwareModel    # e.g., D22AP
```

Or on device: Settings → General → About → Model Name + Software Version

---

## Jailbreak Tool Selection

| Tool | Chip | iOS Versions | Type | Computer Required |
| --- | --- | --- | --- | --- |
| checkra1n | A7–A11 (5s–X) | ANY version | Semi-tethered | Every reboot |
| palera1n | A8–A16 (6–15) | 15.0–17.7 | Semi-tethered | Every reboot |
| Dopamine | A12+ (XS–15) | 15.0–16.6.1 | Semi-untethered | Only first time |

**Recommended for pentesting:**
- Budget: iPhone X (~$60 used) + checkra1n = works on ANY iOS
- Modern: iPhone 12/13 on iOS 16.x + Dopamine = no computer per reboot

---

## Method A: checkra1n (iPhone 5s – iPhone X)

### Requirements

- iPhone 5s through iPhone X (A7–A11 chip)
- USB-A to Lightning cable (USB-C adapters can fail in DFU)
- macOS or Linux host

### A1. Download checkra1n

```bash
# macOS
curl -L -o ~/Downloads/checkra1n.dmg https://assets.checkra.in/downloads/macos/986bc972bfa6c5ebfe87cda626feeee7af1c7de1/checkra1n.dmg
open ~/Downloads/checkra1n.dmg
# Drag checkra1n.app to /Applications
```

### A2. Prepare Device

1. Back up device (iTunes/Finder)
2. For iPhone 8/X on iOS 16+: disable passcode first
    - Settings → Face ID & Passcode → Turn Passcode Off
3. Connect iPhone via USB-A cable

### A3. Enter DFU Mode

checkra1n will guide you, but the manual steps:

**iPhone 8 / X (Face ID / no Home button):**
1. Quick press Volume Up
2. Quick press Volume Down
3. Hold Side button until screen goes black
4. Hold Side + Volume Down for 5 seconds
5. Release Side, keep holding Volume Down for 10 seconds
6. Screen stays black = DFU mode (if Apple logo appears, retry)

**iPhone 7:**
1. Hold Power + Volume Down for 10 seconds
2. Release Power, keep holding Volume Down for 5 seconds

**iPhone 6s and older:**
1. Hold Power + Home for 10 seconds
2. Release Power, keep holding Home for 5 seconds

### A4. Run checkra1n

```bash
# GUI mode
open /Applications/checkra1n.app

# OR CLI mode (useful for automation)
/Applications/checkra1n.app/Contents/MacOS/checkra1n -c
```

**GUI steps:**
1. Click “Start”
2. Follow DFU instructions on screen
3. Wait for exploitation (~30 seconds)
4. Device reboots with checkra1n loader installed

### A5. Install Package Manager

1. On device: open “checkra1n” app (on home screen)
2. Tap “Cydia” or “Sileo” → Install
3. Wait for installation to complete
4. Device resprings

### A6. After Every Reboot

checkra1n is semi-tethered — jailbreak is lost on reboot:

```bash
# Re-jailbreak after reboot:
/Applications/checkra1n.app/Contents/MacOS/checkra1n -c
# Enter DFU → device boots jailbroken again
```

---

## Method B: palera1n (iPhone 8–15, iOS 15–17)

### Requirements

- iPhone 8 or newer (A8–A16)
- iOS 15.0 – 17.7
- macOS (Apple Silicon or Intel)
- USB-A to Lightning cable recommended

### B1. Download palera1n

```bash
curl -L -o ~/Downloads/palera1n \
  https://github.com/palera1n/palera1n/releases/latest/download/palera1n-macos-universal
chmod +x ~/Downloads/palera1n
sudo mv ~/Downloads/palera1n /usr/local/bin/palera1n
```

### B2. First-Time Setup (Create FakeFS)

```bash
# Rootful mode (-f) = full filesystem access (best for pentesting)
# -c = create fakefs (only needed first time)
sudo palera1n -f -c
```

**Process:**
1. Follow DFU instructions shown in terminal
2. palera1n exploits checkm8 → uploads KPF
3. Creates fake filesystem (takes 5-10 minutes)
4. Device reboots automatically

### B3. Boot Jailbroken

```bash
# After fakefs is created, boot jailbroken:
sudo palera1n -f
# Enter DFU when prompted
# Device boots with jailbreak active
```

### B4. Install Package Manager

1. On device: open “palera1n” loader app
2. Tap “Install” → choose Sileo
3. Wait for completion → device resprings

### B5. After Every Reboot

```bash
# Semi-tethered: need computer each reboot
sudo palera1n -f
# Enter DFU → boots jailbroken
```

### B6. Rootful vs Rootless

| Flag | Mode | Access | Best For |
| --- | --- | --- | --- |
| `-f` | Rootful | Full /System write | Pentesting, full control |
| (none) | Rootless | /var/jb only | Daily use, tweak development |

Always use `-f` for security testing.

---

## Method C: Dopamine (iPhone XS–15, iOS 15–16.6.1)

### Requirements

- iPhone XS or newer (A12+ / arm64e)
- iOS 15.0 – 16.6.1 specifically
- TrollStore installed on device

### C1. Install TrollStore

TrollStore is needed first to install Dopamine persistently.

**For iOS 15.0–15.4.1:**

```
1. Open Safari → https://api.jailbreaks.app/troll
2. Install TrollHelper
3. Open TrollHelper → Install TrollStore
```

**For iOS 15.5–16.6.1:**

```
1. Install "Tips" app from App Store (if not present)
2. Open Safari → https://api.jailbreaks.app/troll64e
3. This replaces Tips with TrollHelper
4. Open modified Tips app → Install TrollStore
5. Re-install real Tips from App Store after
```

### C2. Install Dopamine

1. Download Dopamine .tipa from https://ellekit.space/dopamine/
2. Open in TrollStore → tap “Install”
3. Dopamine app appears on home screen

### C3. Jailbreak

1. Open Dopamine app
2. Tap “Jailbreak”
3. Device resprings → jailbroken
4. Sileo is auto-installed

### C4. After Reboot

No computer needed — just reopen Dopamine app and tap “Jailbreak” again.

---

## Post-Jailbreak: Pentest Environment Setup

### 1. SSH Access

```bash
# On Mac — set up SSH tunnel via USB
iproxy 2222 22 &

# Connect (default password: alpine)
ssh root@localhost -p 2222

# IMMEDIATELY change passwords
passwd root       # change from 'alpine'
passwd mobile     # change from 'alpine'
```

### 2. Add Repositories in Sileo

Open Sileo on device → Sources → Add:

```
https://build.frida.re              # Frida
https://repo.chariz.com             # Popular tweaks
https://havoc.app                   # SSL Kill Switch 3
https://cydia.akemi.ai              # A-Bypass (RASP hide)
```

### 3. Install Essential Packages

Via Sileo, install:
- **Frida** (re.frida.server)
- **OpenSSH** (if not already present)
- **AppSync Unified** (install unsigned IPAs)
- **SSL Kill Switch 3** (quick SSL pinning bypass)
- **A-Bypass** or **Liberty Lite** (jailbreak detection bypass)
- **Filza** (filesystem browser)
- **NewTerm** (on-device terminal)

### 4. Verify Frida

```bash
# From Mac:
frida-ps -U
# Should list all running processes on device

# Test injection:
frida -U -n SpringBoard -e "ObjC.classes.NSBundle.mainBundle().bundleIdentifier()"
```

### 5. Burp Suite Proxy Setup

**Export Burp CA certificate:**
1. Burp → Proxy → Options → Import/Export CA → Export as DER
2. Rename to `burp-ca.der`

**Install on device:**

```bash
# Host cert on Mac:
cd /path/to/cert && python3 -m http.server 8888

# On device Safari: http://<mac-ip>:8888/burp-ca.der
# Accept profile installation prompt
```

**Trust certificate:**
1. Settings → General → VPN & Device Management → Install profile
2. Settings → General → About → Certificate Trust Settings → Enable full trust

**Configure proxy on device:**
- Settings → Wi-Fi → (your network) → Configure Proxy → Manual
- Server: `<mac-ip>`, Port: `8080`

### 6. Frida Scripts for Testing

```bash
# SSL pinning bypass (universal)
frida -U -f com.jago.digitalBankingApp \
  -l jago_full_bypass.js --no-pause

# Using objection
pip3 install objection
objection -g com.jago.digitalBankingApp explore
# Then: ios sslpinning disable

# Dump keychain
# Then: ios keychain dump

# List app files
# Then: env
```

---

## Jailbreak Detection Bypass (RASP-Protected Apps)

### Quick Methods

**A-Bypass (Sileo tweak):**
1. Install from repo
2. Settings → A-Bypass → select target apps
3. Respring

**Liberty Lite:**
1. Install from repo
2. Settings → Liberty Lite → enable for target apps

**Choicy (disable tweak injection selectively):**
1. Install Choicy
2. Whitelist/blacklist tweaks per app
3. Useful when jailbreak tweaks cause crashes

### Frida-Based Bypass

```jsx
// Generic jailbreak detection bypass
var paths = [
    "/Applications/Cydia.app",
    "/usr/sbin/sshd",
    "/bin/bash",
    "/etc/apt",
    "/private/var/lib/apt",
    "/usr/bin/ssh",
    "/var/lib/cydia",
    "/.installed_pal1ra1n"
];

// Hook NSFileManager fileExistsAtPath
Interceptor.attach(
  ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function(args) {
        this.path = ObjC.Object(args[2]).toString();
    },
    onLeave: function(retval) {
        for (var i = 0; i < paths.length; i++) {
            if (this.path.indexOf(paths[i]) !== -1) {
                retval.replace(0);
                break;
            }
        }
    }
});

// Hook canOpenURL (cydia://)
Interceptor.attach(
  ObjC.classes.UIApplication['- canOpenURL:'].implementation, {
    onEnter: function(args) {
        this.url = ObjC.Object(args[2]).toString();
    },
    onLeave: function(retval) {
        if (this.url.indexOf("cydia") !== -1 ||
            this.url.indexOf("sileo") !== -1) {
            retval.replace(0);
        }
    }
});

console.log("[*] Jailbreak detection bypass loaded");
```

---

## Troubleshooting

### “Unable to enter DFU mode”

- Use USB-A cable (not USB-C to Lightning)
- Try different USB port
- Remove case from iPhone
- Timing is critical — practice the button sequence

### checkra1n: “Unsupported iOS version” warning

- Click Options → “Allow untested iOS versions”
- checkm8 is hardware exploit, works regardless

### palera1n: “No space for FakeFS”

- Need ~5-10GB free on device
- Delete photos/apps to make space
- Try: `sudo palera1n -f -c --force-revert` then retry

### SSH connection refused

```bash
# Verify usbmuxd
sudo launchctl list | grep usbmuxd

# Restart if needed
sudo launchctl stop com.apple.usbmuxd
sudo launchctl start com.apple.usbmuxd

# Retry
iproxy 2222 22 &
ssh root@localhost -p 2222
```

### Frida: “Failed to spawn”

```bash
# Use bundle ID, not app name:
frida -U -f com.jago.digitalBankingApp --no-pause

# Find bundle ID:
frida-ps -Uai | grep -i jago
```

### App crashes on launch (jailbreak detected)

1. Try A-Bypass or Liberty Lite first
2. If still crashes: use Choicy to disable all tweaks for that app
3. Use Frida-only approach (no Substrate hooks)
4. Last resort: patch binary with Ghidra/Hopper

---

## Quick Reference

| Action | Command |
| --- | --- |
| SSH to device | `iproxy 2222 22 & ssh root@localhost -p 2222` |
| List processes | `frida-ps -U` |
| List installed apps | `frida-ps -Uai` |
| Attach to app | `frida -U -f <bundle.id> -l script.js --no-pause` |
| Objection explore | `objection -g <bundle.id> explore` |
| Disable SSL pinning | `ios sslpinning disable` (in objection) |
| Dump keychain | `ios keychain dump` (in objection) |
| Dump app binary | `frida-ios-dump -u -H 127.0.0.1:2222 <bundle.id>` |
| Install IPA | `ideviceinstaller -i app.ipa` |
| Device logs | `idevicesyslog \| grep <app-name>` |
| Re-jailbreak (checkra1n) | `checkra1n -c` |
| Re-jailbreak (palera1n) | `sudo palera1n -f` |

---

## Recommended Device for Pentesting

**iPhone X (A11) — Best Value:**
- $50-80 used on marketplace
- checkra1n works on ANY iOS (even latest)
- Unpatchable hardware exploit
- Caveat: disable passcode on iOS 16+

**iPhone 12/13 on iOS 16.x — Best Modern:**
- $200-300 used
- Dopamine jailbreak (no computer per reboot)
- arm64e = same arch as current production phones
- Must find one on iOS ≤16.6.1

---

## Key File Locations on Device

| Item | Path |
| --- | --- |
| App bundles | `/var/containers/Bundle/Application/` |
| App data | `/var/mobile/Containers/Data/Application/` |
| Keychain DB | `/var/Keychains/keychain-2.db` |
| Tweak prefs | `/var/mobile/Library/Preferences/` |
| SSL trust store | `/var/mobile/Library/TrustStore/` |