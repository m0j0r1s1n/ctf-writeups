# 🛠 Tools I Use

A reference list of tools in my CTF and pentesting workflow, organised by category.

---

## Reconnaissance & Scanning

| Tool | Use | Install |
|------|-----|---------|
| [RustScan](https://github.com/RustScan/RustScan) | Fast port scanner | `cargo install rustscan` |
| [nmap](https://nmap.org) | Service/version/script scanning | `apt install nmap` |
| [gobuster](https://github.com/OJ/gobuster) | Directory/subdomain fuzzing | `apt install gobuster` |
| [ffuf](https://github.com/ffuf/ffuf) | Web fuzzing | `apt install ffuf` |
| [wfuzz](https://github.com/xmendez/wfuzz) | Web fuzzing with complex payloads | `pip install wfuzz` |

```bash
# My standard nmap one-liner
nmap -p- --min-rate 10000 -sCV -oN nmap_full.txt $TARGET
```

---

## Web Exploitation

| Tool | Use |
|------|-----|
| [Burp Suite](https://portswigger.net/burp) | HTTP proxy, repeater, scanner |
| [sqlmap](https://sqlmap.org) | Automated SQL injection |
| [jwt.io](https://jwt.io) | JWT decode/encode |
| [nikto](https://github.com/sullo/nikto) | Web server scanner |

---

## Binary Exploitation (Pwn)

| Tool | Use | Install |
|------|-----|---------|
| [pwntools](https://github.com/Gallopsled/pwntools) | Exploit scripting | `pip install pwntools` |
| [pwndbg](https://github.com/pwndbg/pwndbg) | GDB plugin for pwn | See GitHub |
| [Ghidra](https://ghidra-sre.org) | Decompiler / reverse engineering | Download from NSA |
| [checksec](https://github.com/slimm609/checksec) | Check binary mitigations | `apt install checksec` |
| [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) | Find ROP gadgets | `pip install ropgadget` |

```bash
# Quick binary recon
file binary && checksec binary && strings binary | grep -i flag
```

---

## Cryptography

| Tool | Use |
|------|-----|
| [CyberChef](https://gchq.github.io/CyberChef/) | Browser crypto swiss-army knife |
| [hashcat](https://hashcat.net) | GPU password cracking |
| [john](https://www.openwall.com/john/) | CPU password cracking |
| Python `pycryptodome` | Crypto primitives |

```bash
# Common hashcat modes
hashcat -m 0     # MD5
hashcat -m 1000  # NTLM
hashcat -m 1800  # sha512crypt
hashcat -m 16500 # JWT HS256
hashcat -m 124   # Django SHA1
```

---

## Post-Exploitation & Priv Esc

| Tool | Use |
|------|-----|
| [linpeas](https://github.com/carlospolop/PEASS-ng) | Linux priv esc enumeration |
| [linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester) | Kernel exploit suggestions |
| [pspy](https://github.com/DominicBreuker/pspy) | Monitor processes without root |
| [chisel](https://github.com/jpillora/chisel) | TCP tunnelling / port forwarding |

```bash
# Quick priv esc checks
sudo -l
find / -perm -4000 2>/dev/null   # SUID binaries
crontab -l && cat /etc/crontab
```

---

## Wordlists

- [SecLists](https://github.com/danielmiessler/SecLists) — the essential collection
- `rockyou.txt` — `/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt`

---

## My Setup

- **OS**: Kali Linux (main) + Ubuntu (daily)
- **Terminal**: tmux
- **Editor**: Neovim
- **Note-taking**: These HonKit pages + Obsidian locally
