# AppSec: RootAVD Setup Guide

# rootAVD Setup Guide — Android 16 (API 36.1) on Apple Silicon

## Environment

- MacBook Pro M4, 16GB RAM, macOS 15.7.7
- Android Studio Emulator (AVD) — arm64-v8a
- System Image: `google_apis_playstore` API 36.1
- Magisk: v30.7 (required for Android 16 support)
- rootAVD: latest from GitLab

## Prerequisites

- Android Studio installed with emulator + platform-tools
- AVD created (e.g., `Medium_Phone_API_36.1`)
- System image: `system-images/android-36.1/google_apis_playstore/arm64-v8a`

---

## Step 1: Download rootAVD

```bash
cd ~
curl -L -o rootAVD.zip "https://gitlab.com/newbit/rootAVD/-/archive/master/rootAVD-master.zip"
unzip -o rootAVD.zip -d rootAVD-tmp
mv rootAVD-tmp/rootAVD-master ~/rootAVD
rm -rf rootAVD-tmp rootAVD.zip
chmod +x ~/rootAVD/rootAVD.sh
```

## Step 2: Download Magisk v30.7 (or latest)

**Critical**: Magisk v26.4 (bundled with rootAVD) does NOT boot on Android 16.
Magisk v28.1 also fails. You need v30.7+.

```bash
curl -L -o ~/rootAVD/Magisk.zip \
  "https://github.com/topjohnwu/Magisk/releases/download/v30.7/Magisk-v30.7.apk"
```

This replaces the bundled `Magisk.zip` with the newer version.

## Step 3: Start the Emulator (with display)

The emulator must be running with ADB accessible for rootAVD to patch.
Use a visible window — you’ll need it later for Magisk UI setup.

```bash
export PATH=~/Library/Android/sdk/emulator:~/Library/Android/sdk/platform-tools:$PATH
emulator -avd Medium_Phone_API_36.1 -no-audio -no-snapshot &
```

Wait for boot:

```bash
adb wait-for-device
while [ "$(adb shell getprop sys.boot_completed | tr -d '\r')" != "1" ]; do sleep 3; done
echo "Boot complete"
```

## Step 4: Patch the Ramdisk with rootAVD

```bash
cd ~/rootAVD
export PATH=~/Library/Android/sdk/platform-tools:$PATH
./rootAVD.sh system-images/android-36.1/google_apis_playstore/arm64-v8a/ramdisk.img
```

Expected output should show:
- `rootAVD with Magisk '30.7' Installer`
- `Ramdisk.img uses lz4_legacy compression`
- `patching the ramdisk with Magisk Init`
- `Install all APKs placed in the Apps folder`
- `Performing Streamed Install` → `Success`

The emulator will attempt to shut down after patching.

## Step 5: Cold Boot with Patched Ramdisk

Kill existing emulator if still running, then restart:

```bash
adb kill-server && adb start-server
emulator -avd Medium_Phone_API_36.1 -no-audio -no-snapshot &
```

**Important**: Always use `-no-snapshot` to force boot from patched ramdisk.

Wait for boot completion again.

## Step 6: Magisk “Additional Setup” Dialog

On first boot with patched ramdisk, Magisk will show a dialog:
> “Requires additional setup — Your device needs additional setup for Magisk to work properly. Do you want to proceed and reboot?”

Tap **OK**. The device reboots automatically.

Wait for boot to complete again.

## Step 7: Configure Magisk Settings

Open Magisk app:

```bash
adb shell am start -n com.topjohnwu.magisk/.ui.MainActivity
```

Navigate to **Settings** (gear icon):

1. Scroll to **Superuser** section
2. Verify **Superuser access** = “Apps and ADB”
3. Change **Automatic response** → “Grant”
4. Verify **Mount namespace mode** = “Global namespace”

## Step 8: Grant Root to Shell

Navigate to the **Superuser** tab (bottom nav, shield icon).

Initially, `com.android.shell` may not be listed or may show as denied.
To trigger a grant:

1. If Shell is listed with toggle OFF → tap the toggle to ON
2. If not listed → run `adb shell su -c id` (it will fail but registers shell)
3. Then tap the toggle ON in the Superuser tab

**Verify toast**: “Superuser rights of Shell are granted”

## Step 9: Verify Root

```bash
adb shell "su -c 'id'"
# Expected: uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0

adb shell "su -c 'magisk -v'"
# Expected: 30.7:MAGISK:R

adb shell "su -c 'getenforce'"
# Expected: Enforcing
```

---

## Pitfalls & Troubleshooting

### 1. Emulator won’t boot after patching (device stays “offline”)

**Cause**: Magisk version incompatible with Android 16.
**Fix**: Must use Magisk v30.7+. Restore and re-patch:

```bash
cd ~/rootAVD
./rootAVD.sh system-images/android-36.1/google_apis_playstore/arm64-v8a/ramdisk.img restore
```

### 2. “A snapshot operation is pending and timeout expired”

**Cause**: Stale snapshot lock files.
**Fix**:

```bash
rm -rf ~/.android/avd/Medium_Phone_API_36.1.avd/snapshots/default_boot
rm -f ~/.android/avd/Medium_Phone_API_36.1.avd/*.lock
```

### 3. `su: inaccessible or not found`

**Cause**: Magisk hasn’t completed initial setup yet.
**Fix**: Open Magisk app, accept “Additional setup” dialog, reboot.

### 4. `su: request rejected (2000)` in logcat

**Cause**: Shell not granted in Magisk policy despite “Automatic response = Grant”.
**Fix**: Go to Superuser tab in Magisk app, toggle Shell permission OFF then ON again.

### 5. `adb root` returns “cannot run as root in production builds”

**Expected behavior** on `google_apis_playstore` images. Use `su` via Magisk instead.

---

## Quick Reference

| Action | Command |
| --- | --- |
| Start emulator | `emulator -avd Medium_Phone_API_36.1 -no-audio -no-snapshot` |
| Verify root | `adb shell "su -c 'id'"` |
| Restore stock | `cd ~/rootAVD && ./rootAVD.sh system-images/android-36.1/google_apis_playstore/arm64-v8a/ramdisk.img restore` |
| Open Magisk | `adb shell am start -n com.topjohnwu.magisk/.ui.MainActivity` |
| Check Magisk logs | `adb logcat -d \| grep -i magisk` |

---

## Next Steps (Pentest Setup)

1. **Frida Server**: Download arm64 binary, push to `/data/local/tmp/`
2. **Burp Proxy**: `adb shell settings put global http_proxy <IP>:8080`
3. **Shamiko Module**: Install via Magisk Modules for root hiding
4. **DenyList**: Add target apps to hide Magisk from RASP detection
5. **SSL Pinning Bypass**: Use existing Frida scripts (e.g., `jago_full_bypass.js`)