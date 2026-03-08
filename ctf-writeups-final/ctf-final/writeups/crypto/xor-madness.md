# XOR Madness

## Difficulty: Easy
## Category: Cryptography

---

## Overview

A classic XOR encryption challenge. Given a ciphertext and a repeating key scenario, recover the plaintext by exploiting weaknesses in XOR-based encryption.

---

## The Challenge

```
Encrypted (hex):
1a0e1c0b451a114516001b0e05450b0e04451c181b080e14
```

---

## Understanding XOR

The core property we exploit:

```
plaintext XOR key = ciphertext
ciphertext XOR key = plaintext       # XOR is reversible
ciphertext XOR plaintext = key       # if we know plaintext
```

If the same short key is reused across a longer message (repeating-key XOR), it's vulnerable to frequency analysis.

---

## Breaking the Key

Once we know the key length, treat every `keylen`-th byte as encrypted with the same single byte:

```python
from itertools import cycle

ciphertext = bytes.fromhex("1a0e1c0b451a114516001b0e05450b0e04451c181b080e14")

def single_xor_score(data):
    score = 0
    for byte in data:
        if chr(byte).lower() in 'etaoin shrdlu':
            score += 1
    return score

def crack_single_xor(data):
    best = (0, 0, b'')
    for key in range(256):
        candidate = bytes(b ^ key for b in data)
        score = single_xor_score(candidate)
        if score > best[0]:
            best = (score, key, candidate)
    return best

keylen = 5
key_bytes = []
for i in range(keylen):
    chunk = ciphertext[i::keylen]
    _, k, _ = crack_single_xor(chunk)
    key_bytes.append(k)

key = bytes(key_bytes)
plaintext = bytes(c ^ k for c, k in zip(ciphertext, cycle(key)))
print(f"Key: {key}")
print(f"Flag: {plaintext.decode()}")
```

---

## Key Takeaways

- Repeating-key XOR is fundamentally broken against frequency analysis
- If you know any part of the plaintext (e.g. `HTB{`), XOR it against the ciphertext to immediately reveal key bytes
- `ciphertext XOR ciphertext` (two messages, same key) completely eliminates the key
- CyberChef is great for quick XOR experiments

## Tools Used

| Tool | Purpose |
|------|---------|
| Python 3 | Scripting the attack |
| `pwntools` | `xor()` helper |
| CyberChef | Quick browser experiments |
