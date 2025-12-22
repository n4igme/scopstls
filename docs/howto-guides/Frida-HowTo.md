# Frida How-To Guide

Frida is a dynamic instrumentation toolkit that allows you to inject JavaScript or custom libraries into applications to inspect and modify their behavior at runtime.

## Installation

```bash
# Using pip
pip install frida-tools  # Includes frida-tools like frida, frida-trace, etc.

# Using npm
npm install frida

# Or install frida-tools for command-line utilities
pip3 install frida-tools
```

## Basic Frida Script Structure

```javascript
// Template for basic Frida script
setTimeout(function() {
    // Prevent Java/Swift/etc. from running until we're ready
    Java.perform(function() {
        // Your code here
    });
}, 0);
```

## Real-World Scenario 1: Bypassing SSL Pinning in Android App

**Situation**: You're testing an Android application that implements SSL pinning, preventing you from intercepting HTTPS traffic with a proxy like Burp Suite.

**Step-by-Step Process**:

1. **Identify the target app**:
```bash
# List running processes to find the app
frida-ps -U  # For USB connected device
# or
frida-ps -R  # For remote device
```

2. **Create the SSL bypass script**:
```javascript
// ssl_pinning_bypass.js
setTimeout(function() {
    Java.perform(function() {
        console.log("[.] SSL Pinning Bypass");

        // OkHTTP (very common)
        var okhttp3_CertificatePinner = Java.use("okhttp3.CertificatePinner");
        okhttp3_CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
            console.log("[+] OkHTTP 3.x CertificatePinner.check() called. Not throwing an exception.");
            return;
        };

        // TrustManagerImpl (Android 7+)
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, target, authType) {
            console.log("[+] TrustManagerImpl.verifyChain() called. Not throwing an exception.");
            return untrustedChain;
        };

        // Android Network Security Config (Android 7+)
        try {
            var NetworkSecurityTrustManager = Java.use("android.security.net.config.NetworkSecurityTrustManager");
            NetworkSecurityTrustManager.checkPins.overload('java.util.List').implementation = function(pins) {
                console.log("[+] NetworkSecurityTrustManager.checkPins() called. Not throwing an exception.");
                return true;
            };
        } catch (err) {
            console.log("[-] NetworkSecurityTrustManager not found: " + err);
        }

        // Appcelerator Titanium
        try {
            var appcelerator_PinningTrustManager = Java.use("appcelerator.https.PinningTrustManager");
            appcelerator_PinningTrustManager.checkServerTrusted.implementation = function() {
                console.log("[+] Appcelerator PinningTrustManager bypassed.");
            };
        } catch (err) {
            console.log("[-] Appcelerator PinningTrustManager not found: " + err);
        }
    });
}, 0);
```

3. **Run the script**:
```bash
# Attach to running app
frida -U -n "com.example.app" -l ssl_pinning_bypass.js

# Or spawn the app with the script
frida -U -f com.example.app -l ssl_pinning_bypass.js --no-pause
```

## Real-World Scenario 2: Hooking Crypto Functions to Extract Keys

**Situation**: You want to extract encryption keys from an application to understand how it protects sensitive data.

**Step 1**: Create a script to hook cryptographic functions:
```javascript
// crypto_hook.js
setTimeout(function() {
    Java.perform(function() {
        console.log("[.] Hooking crypto functions to extract keys");

        // Hook AES key generation
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algorithm) {
            console.log("[+] AES Key found: " + bytesToString(key) + " | Algorithm: " + algorithm);
            return this.$init(key, algorithm);
        };

        // Hook key generation
        var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        KeyGenerator.generateKey.implementation = function() {
            var result = this.generateKey();
            console.log("[+] Generated Key: " + result);
            return result;
        };

        // Hook Base64 encoding/decoding (often used with keys)
        var Base64 = Java.use("android.util.Base64");
        Base64.encode.overload('[B', 'int').implementation = function(input, flags) {
            console.log("[+] Base64 Encode called with: " + bytesToString(input));
            var result = this.encode(input, flags);
            console.log("[+] Base64 Encoded result: " + result);
            return result;
        };

        // Helper function to convert byte array to string
        function bytesToString(array) {
            var result = "";
            for (var i = 0; i < array.length; i++) {
                if (array[i] >= 0x20 && array[i] < 0x7f) {
                    result += String.fromCharCode(array[i]);
                } else {
                    result += "\\x" + array[i].toString(16).padStart(2, '0');
                }
            }
            return result;
        }
    });
}, 0);
```

**Step 2**: Run and analyze:
```bash
# Start the app with the crypto hook
frida -U -f com.example.app -l crypto_hook.js --no-pause

# Watch for key extraction in the console output
```

## Advanced Frida Techniques

**Memory dumping and modification**:
```javascript
// memory_operations.js
setTimeout(function() {
    var isARM64 = Process.arch === 'arm64';
    console.log("Architecture: " + Process.arch);
    
    // Find and hook native function
    var exports = Module.enumerateExportsSync("libtarget.so");
    
    exports.forEach(function(exp) {
        if (exp.name.indexOf("targetFunction") !== -1) {
            console.log("Found function: " + exp.name + " at " + exp.address);
            
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    console.log("targetFunction called with arg0: " + args[0]);
                },
                onLeave: function(retval) {
                    console.log("targetFunction returned: " + retval);
                }
            });
        }
    });
}, 0);
```

## Common Frida Patterns

### Hooking Constructor/Initialization Functions
```javascript
var TargetClass = Java.use("com.target.Class");
TargetClass.$init.implementation = function() {
    console.log("[+] TargetClass initialized");
    return this.$init();
};
```

### Enumerating Loaded Classes
```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(aClass) {
            console.log(aClass);
        },
        onComplete: function() {
            console.log("Class enumeration completed");
        }
    });
});
```

### Finding Memory Allocations
```javascript
var found = false;
var base_address = null;

Process.enumerateMallocedRanges({
    onMatch: function(range) {
        if (!found && range.size > 10000) { // Look for large allocations
            base_address = range.base;
            found = true;
            console.log("Found memory at: " + range.base);
        }
    },
    onComplete: function() {
        console.log("Memory enumeration completed");
    }
});
```

## Tips and Best Practices

1. **Always wrap in Java.perform()**: Ensure all Java operations are performed on the main thread
2. **Handle exceptions gracefully**: Wrap code in try-catch blocks to prevent app crashes
3. **Use proper cleanup**: Some hooks may need to be removed after use
4. **Be careful with performance**: Heavy instrumentation can slow down the target application
5. **Consider the timing**: Some functions may not exist until certain actions are taken in the app
6. **Use frida-trace for quick exploration**: Before writing complex scripts, use frida-trace to understand application behavior
7. **Be aware of anti-debugging**: Some applications include anti-Frida protections

## Troubleshooting Common Issues

- **"Failed to enumerate classes"**: App might be using class encryption or loader obfuscation
- **Hooks not triggering**: Functions might be in native code or not yet loaded
- **App crashes**: Instrumentation code might be interfering with normal app execution
- **Architecture mismatches**: Ensure you're using the right Frida server for the device architecture
- **Permission errors**: On some devices, additional permissions or root access might be required