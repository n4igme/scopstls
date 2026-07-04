# AppSec: Windows ARM Lab Setup Guide

# Windows ARM 25H2 Lab Setup — ttest/xdev on Apple Silicon (UTM)

## Environment

- MacBook Pro M4, 16GB RAM, macOS 15.7.7
- UTM hypervisor (Apple Virtualization framework)
- Windows 11 ARM 25H2 (build 26100+)
- Shared folder: `~/PlayGround` mounted as `Z:` via SPICE WebDAV
- Host IP on VM network: `192.168.64.1`

## Purpose

Lab environment for:
- **ttest** — thick client penetration testing (.NET, Java, Electron, native Windows apps)
- **xdev** — exploit development (ARM64 Windows targets only)

## Architecture Constraints

| Target Type | Viable | Notes |
|-------------|--------|-------|
| .NET apps (WinForms/WPF/MAUI) | Yes | Managed code, architecture-agnostic |
| Java apps (Swing/JavaFX) | Yes | JVM runs natively on ARM |
| Electron apps | Yes | asar extract, DevTools, hooks all work |
| Native x86/x64 apps (analysis) | Yes | Prism emulation handles runtime |
| ARM64 exploit development | Yes | Native architecture match |
| x86/x64 exploit development | No | Allocator/heap behavior differs under emulation |
| x86/x64 kernel exploits | No | Different kernel, pool layout, gadgets |

---

## Prerequisites

- UTM installed (`/Applications/UTM.app`)
- Windows 11 ARM ISO (25H2) — installed and bootable in UTM
- Shared directory configured: UTM → VM Settings → Sharing → `~/PlayGround`
- Burp Suite running on macOS host
- Burp CA certificate exported as DER: `~/PlayGround/shared-lab/burp-certs/burp_cacert.der`

---

## Step 1: UTM VM Configuration

Recommended VM settings (UTM → right-click VM → Edit):

| Setting | Value |
|---------|-------|
| CPU | 4-6 cores |
| RAM | 8-16 GB |
| Disk | 80-100 GB |
| Network | Shared Network (NAT) |
| Sharing | Directory Share → `~/PlayGround` |
| Display | SPICE (for clipboard + shared folder) |

---

## Step 2: Verify Shared Folder Access

After booting the VM, the shared folder mounts via SPICE WebDAV at:

```
\\localhost@9843\DavWWWRoot
```

Map it as Z: drive (usually auto-mapped, verify with):

```powershell
Get-PSDrive Z
# Should show: \\localhost@9843\DavWWWRoot
```

If not mapped:

```powershell
net use Z: \\localhost@9843\DavWWWRoot /persistent:yes
```

Verify scripts are accessible:

```powershell
dir Z:\shared-lab\scripts\
```

---

## Step 3: Disable Security Defenses

> **IMPORTANT:** Disable Tamper Protection manually first:
> Settings → Privacy & Security → Windows Security → Virus & threat protection → Manage settings → **Tamper Protection → OFF**

Open an **elevated PowerShell** (Run as Administrator):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
cd Z:\shared-lab\scripts
.\01-disable-defenses.ps1
```

### What it disables:

| Defense | Method |
|---------|--------|
| Windows Defender RT | `Set-MpPreference` + registry keys |
| SmartScreen | Registry: `SmartScreenEnabled = Off` |
| AMSI | Registry: `AmsiEnable = 0` |
| UAC | Registry: `EnableLUA = 0` |
| Windows Firewall | `Set-NetFirewallProfile -Enabled False` |
| Windows Update | Service disabled + registry |
| Developer Mode | Registry: `AllowDevelopmentWithoutDevLicense = 1` |

### Reboot after completion:

```powershell
shutdown /r /t 5
```

---

## Step 4: Install Tool Chain

After reboot, open elevated PowerShell:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
cd Z:\shared-lab\scripts
.\02-install-tools.ps1
```

### Tools installed:

| Category | Tools |
|----------|-------|
| Package Manager | Chocolatey |
| Runtime | Python 3.12, Git, Java 17 (Temurin JRE) |
| .NET Reversing | ILSpy (+ dnSpyEx manual download) |
| Monitoring | Sysinternals Suite, System Informer |
| Debuggers | WinDbg Preview (ARM64 native), x64dbg |
| Network | Wireshark + Npcap |
| Hooking | Frida, Objection |
| Reverse Engineering | Ghidra |
| Editors | VSCode, Notepad++, 7zip |
| Exploit Dev | pwntools, ropper, capstone, keystone, unicorn |
| Build | VS 2022 Build Tools (add ARM64 C++ workload manually) |

### Post-install: Fix Java PATH

If `java -version` fails after install:

```powershell
$javaPath = "C:\Program Files\Eclipse Adoptium\jre-17.0.17.10-hotspot\bin"
[System.Environment]::SetEnvironmentVariable("Path", $env:Path + ";$javaPath", "Machine")
[System.Environment]::SetEnvironmentVariable("JAVA_HOME", "C:\Program Files\Eclipse Adoptium\jre-17.0.17.10-hotspot", "Machine")
$env:Path += ";$javaPath"
java -version
```

### Manual steps:

1. Download dnSpyEx from https://github.com/dnSpyEx/dnSpy/releases/latest
2. VS Build Tools → Visual Studio Installer → add:
   - Desktop development with C++
   - MSVC ARM64 build tools
   - Windows 11 SDK

---

## Step 5: Configure Network / Proxy

Ensure Burp Suite is running on macOS host with listener on **all interfaces, port 8080**:
- Burp → Proxy → Settings → Proxy Listeners → Edit → Bind to: All interfaces

Then in the VM:

```powershell
.\03-configure-network.ps1 -BurpCertPath "Z:\shared-lab\burp-certs\burp_cacert.der"
```

### What it configures:

| Component | Setting |
|-----------|---------|
| System proxy (WinHTTP) | `192.168.64.1:8080` |
| IE/WinINET proxy | Same (registry) |
| Burp CA cert | Imported to Trusted Root store |
| Java cacerts | Burp CA added (if JAVA_HOME set) |
| Environment variables | `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` |

### Verify proxy works:

```powershell
curl.exe -x http://192.168.64.1:8080 http://httpbin.org/ip
```

Should appear in Burp's HTTP history on macOS.

---

## Step 6: Verify Setup

```powershell
.\04-verify-setup.ps1
```

### Expected output (all checks):

```
[Defenses]
  Defender RT disabled... OK
  UAC disabled... OK
  Firewall disabled... OK
  SmartScreen disabled... OK

[Core Tools]
  Python 3... OK
  Git... OK
  Java... OK

[ttest Tools]
  Frida... OK
  Objection... OK
  ILSpy... OK/WARN
  Wireshark... OK/WARN
  x64dbg... OK/WARN

[xdev Tools]
  pwntools... OK/WARN
  ropper... OK/WARN
  Ghidra... OK/WARN

[Network / Proxy]
  System proxy configured... OK
  Proxy reachable... OK

Results: PASS: 14+  WARN: 0-3  FAIL: 0
```

FAIL = 0 required before proceeding.

---

## Step 7: Take Snapshot

In UTM on macOS, take a snapshot named **`tools-ready`**:

- Right-click WIN25H2 → Take Snapshot → Name: `tools-ready`

### Snapshot strategy:

| Name | When | Purpose |
|------|------|---------|
| `clean-install` | Before any modifications | Pristine Windows restore |
| `tools-ready` | After Step 6 passes | Lab baseline |
| `pre-{engagement}` | Before loading target app | Per-engagement rollback |

---

## Step 8: Enable WinRM Remote Access (Optional)

Enables Hermes to drive the VM remotely from macOS — run PoCs, compile DLLs, and collect evidence without switching windows.

In the VM (elevated PowerShell):

```powershell
# Change network to Private (required for WinRM)
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

# Enable WinRM
Enable-PSRemoting -Force
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'

# Verify
winrm quickconfig
ipconfig | findstr "IPv4"
```

From macOS, verify connectivity:

```bash
# Quick test via curl (SOAP)
curl -s -u 'nana:nana' \
  -H "Content-Type: application/soap+xml;charset=UTF-8" \
  http://192.168.64.5:5985/wsman
```

Or use Python `pywinrm` / PowerShell `Enter-PSSession` for interactive access.

**Credentials:** `nana` / `nana` (lab only — never use weak creds in production)

---

## DLL Hijack PoC Compilation (mingw on ARM64)

Key lessons from live testing:

**Working approach (no .def file, no header conflicts):**

```c
// hijack.c - self-contained, no windows.h version headers
// Define types manually to avoid conflicts
typedef unsigned long DWORD;
typedef void* HANDLE;
// ... (see hijack.c in shared-lab/targets/BGInfo/)

// Export stubs forward to real System32\version.dll at runtime
void* GetFileVersionInfoA(void) { LoadReal(); return ...; }

// DllMain writes proof file on attach
BOOL WINAPI DllMain(...) { WriteProof(); return TRUE; }
```

**Compile command:**

```powershell
& "C:\ProgramData\mingw64\mingw64\bin\gcc.exe" -shared -o VERSION.dll hijack.c -lkernel32
```

**Why .def files fail over WebDAV:** SPICE WebDAV mangles line endings and encoding. Files written on macOS arrive with invisible BOM/encoding artifacts that the linker rejects. Solution: write source files locally on the VM, or compile without .def (export via function definitions).

**Why `#pragma comment(linker, "/export:...")` fails:** This is MSVC-only syntax. Mingw ignores it silently — the DLL compiles but has no exports, so Windows falls back to the system DLL.

---

## Usage

### Starting a ttest engagement:

1. Drop target binary in `~/PlayGround/shared-lab/targets/` (macOS side)
2. In VM, access at `Z:\shared-lab\targets\`
3. Install/run the target application
4. Start Burp on macOS, verify intercepts
5. Begin `ttest start` from Hermes

### Starting an xdev engagement:

1. Place crash PoC / vulnerable binary in `~/PlayGround/shared-lab/targets/`
2. Ensure target is ARM64 Windows binary (check with `dumpbin /headers` or `file`)
3. Use WinDbg for debugging, Ghidra for static analysis
4. Begin `xdev start` from Hermes

### Proxy routing for specific app types:

```powershell
# .NET apps (auto-detect system proxy)
# Usually no extra config needed

# Java apps (manual proxy)
java -Dhttps.proxyHost=192.168.64.1 -Dhttps.proxyPort=8080 -jar target.jar

# Electron apps
target.exe --proxy-server="http://192.168.64.1:8080"

# Apps that ignore system proxy → use Proxifier
choco install proxifier -y
# Configure per-process proxy rules
```

---

## Important: Proxy Bypass for Package Installs

The system proxy routes all traffic through Burp. This **breaks choco/winget/pip** if Burp isn't running or isn't forwarding. Always disable proxy before installing packages:

```powershell
# Disable proxy temporarily
netsh winhttp reset proxy
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0
$env:HTTP_PROXY = ""
$env:HTTPS_PROXY = ""

# Install what you need
choco install <package> -y

# Re-enable proxy when ready for traffic testing
netsh winhttp set proxy "192.168.64.1:8080" "localhost;127.0.0.1;*.local"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
$env:HTTP_PROXY = "http://192.168.64.1:8080"
$env:HTTPS_PROXY = "http://192.168.64.1:8080"
```

---

## Important: Always Execute PoCs from Local Disk

Windows silently blocks DLL search-order loading from WebDAV/UNC paths (the Z: shared drive). Frida injection and Process Monitor also behave differently on network paths.

**Rule:** Always copy target binary + PoC artifacts to a local directory before testing:

```powershell
mkdir C:\test-<appname> -Force
copy Z:\shared-lab\targets\<app>\* C:\test-<appname>\
cd C:\test-<appname>
# Now run PoCs from here
```

This applies to:
- DLL hijack PoCs (DLL search order skips network drives)
- Frida injection (may fail on network-hosted binaries)
- Process Monitor capture (network I/O noise obscures results)
- Any runtime hooking or patching

---

## Important: ARM64 Compilation Constraints

| Scenario | Solution |
|----------|----------|
| Target is PE32 x86 | Install VS Build Tools with x86 cross-compiler (`vcvarsall.bat x86`) or cross-compile from macOS: `brew install mingw-w64 && i686-w64-mingw32-gcc -shared -o output.dll source.c` |
| Target is PE64 x64 | Use mingw on the VM: `choco install mingw -y` then `gcc -shared -o output.dll source.c` (produces x64) |
| Target is ARM64 | Compile natively with VS Build Tools ARM64 workload or mingw default on ARM64 |

Note: mingw installed via choco on ARM64 Windows produces **x64 DLLs only** (no `-m32` support). For x86 targets, use the 64-bit variant of the target app (if available) or cross-compile from macOS.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Scripts fail with "running scripts is disabled" | `Set-ExecutionPolicy Bypass -Scope Process -Force` — resets after reboot, must re-run each session |
| Unicode/encoding errors in scripts over WebDAV | Avoid em-dashes and special chars in .ps1 files; if issue persists, copy scripts to `C:\temp\` and run locally |
| Proxy not intercepting | Verify Burp listener is on all interfaces; check `curl.exe -x http://192.168.64.1:8080 http://httpbin.org/ip` |
| choco/pip fails with "connection refused 192.168.64.1:8080" | Proxy is routing installs through Burp — disable proxy first (see section above) |
| Java not in PATH after install | Restart PowerShell or refresh: `$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")` |
| PATH changes not taking effect | Machine-level PATH changes require new PowerShell session — close and reopen, or use the refresh command above |
| Z: drive not accessible | Check UTM sharing is enabled; try `net use Z: \\localhost@9843\DavWWWRoot /persistent:yes` |
| DLL hijack proof file not created | Target is running from network drive — copy to local path first (see section above) |
| Defender re-enables after update | Tamper Protection re-enabled; disable manually first, re-run `01-disable-defenses.ps1` |
| Tools blocked by SmartScreen/AV | Verify defenses are off with `04-verify-setup.ps1`; may need to restore snapshot and redo |
| VM network unreachable from host | VM must use Shared Network (not Emulated VLAN); check UTM network settings |
| mingw `gcc` not found after install | Use full path: `& "C:\ProgramData\mingw64\mingw64\bin\gcc.exe"` or open new PowerShell |

---

## References

- Scripts location: `~/PlayGround/shared-lab/scripts/`
- Burp CA cert: `~/PlayGround/shared-lab/burp-certs/burp_cacert.der`
- ttest skill: `~/.hermes/skills/security/ttest/SKILL.md`
- xdev skill: `~/.hermes/skills/security/xdev/SKILL.md`
