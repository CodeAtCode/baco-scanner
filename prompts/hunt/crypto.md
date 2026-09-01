# Cryptographic Weakness Vulnerability Hunt Prompt

## Hunt Instructions

HUNT FOR CRYPTOGRAPHIC VULNERABILITIES ONLY.

Attack class: Cryptographic Weakness (weak algo, hardcoded keys, predictable randomness)
Task: Analyze this code and report ONLY cryptographic vulnerabilities.

DANGEROUS APIs BY LANGUAGE:
- C/C++: rand()/srand() for security, MD5()/SHA1() for passwords, DES/RC4 encryption, hardcoded keys
- Python: random.random() for tokens, hashlib.md5/sha1(password), Crypto.Cipher.DES/RC4, SECRET_KEY hardcode
- Java: java.util.Random for tokens, MessageDigest("MD5"/"SHA-1"), DES/RC4/EBC mode, TrustAllManager
- Go: math/rand instead of crypto/rand, crypto/md5/sha1 for security, cipher.NewRC4(), InsecureSkipVerify:true
- Node.js: Math.random() for tokens, createHash('md5'/'sha1'), createCipher('des-ecb'), weak JWT algorithms

SAFE PATTERNS (DO NOT REPORT):
- Secure RNG: secrets.token_hex(), crypto.getRandomValues(), crypto/rand
- Modern hashing: bcrypt, argon2, scrypt, PBKDF2 for passwords
- Strong encryption: AES-GCM, AES-256-CBC with HMAC, ChaCha20-Poly1305
- Proper TLS: Valid certificate verification, strong cipher suites

BYPASS DETECTION PATTERNS:
- Hash collisions: MD5 collision attacks for certificate forgery
- Rainbow tables: Unsalted hashes vulnerable to precomputation
- Timing attacks: Non-constant-time string comparison for tokens
- Padding oracle: CBC padding oracle attacks
- ECB mode: Patterns visible in encrypted data

CHAIN OPPORTUNITIES:
- Weak hashing → Credential cracking, password recovery
- Weak RNG → Session token prediction, session hijacking
- Hardcoded keys → Data decryption, full system compromise
- Timing attacks → Token recovery, authentication bypass

Return JSON array with format:
[
  {
    "severity": "critical|high|medium|low",
    "title": "crypto vulnerability title",
    "description": "detailed explanation of the crypto flaw",
    "line": line_number,
    "cwe_id": "CWE-XXX",
    "confidence": 0.0-1.0
  }
]

CRITICAL: ONLY report cryptographic vulnerabilities. Ignore all other attack classes.

## Scope — stay in your lane

OWNED CLASS: Weak cryptographic algorithms (MD5, SHA1, DES, RC4), predictable randomness, hardcoded keys/secrets, timing attacks on crypto.
Anything outside this list is not your finding — if you trip over an adjacent issue (key leakage via injection, auth bypass via weak session tokens), emit it at info severity with title prefix '[handoff: <domain>]' and move on. Staying in lane keeps precision and token cost down.

Code input will be provided at runtime.

---

# Cryptographic Weakness Vulnerability Hunt Guide

## Dangerous API Patterns by Language

### C/C++
- **Random Number Generation**: `rand()`, `srand(time(NULL))` for security purposes
- **Hash Functions**: `MD5()`, `SHA1()` for password hashing, integrity verification
- **Encryption**: `EVP_CIPHER_CTX_init()` with DES, RC4, CBC mode without HMAC
- **Key Management**: Hardcoded encryption keys, keys in source code
- **Memory**: Storing plaintext keys in memory, insufficient key clearing

### Python
- **Random**: `random.random()`, `random.randint()` for tokens/secrets
- **Hash**: `hashlib.md5()`, `hashlib.sha1()` for passwords
- **Encryption**: `Crypto.Cipher.DES`, `Crypto.Cipher.ARC4`
- **Key Derivation**: `hashlib.md5(password)` instead of `bcrypt`/`argon2`
- **Hardcoded Keys**: `SECRET_KEY = "abc123"`, `API_KEY = "..."`

### Java
- **Random**: `java.util.Random` for security tokens
- **Hash**: `MessageDigest.getInstance("MD5")`, `SHA-1`
- **Encryption**: `Cipher.getInstance("DES/ECB/PKCS5Padding")`, `RC4`
- **KeyStore**: Hardcoded keystore passwords, weak key storage
- **SSL**: `TrustAllManager`, `hostnameVerifier = (a, b) -> true`

### Go
- **Random**: `math/rand` instead of `crypto/rand`
- **Hash**: `crypto/md5`, `crypto/sha1` for security purposes
- **Encryption**: `cipher.NewRC4()`, ECB mode usage
- **Key Derivation**: `md5.Sum(password)` instead of `bcrypt`
- **TLS**: `tls.Config{InsecureSkipVerify: true}`

### JavaScript/Node.js
- **Random**: `Math.random()` for tokens/secrets
- **Hash**: `crypto.createHash('md5')`, `createHash('sha1')`
- **Encryption**: `crypto.createCipher('des-ecb', key)`
- **JWT**: Weak algorithms, missing signature verification
- **Hardcoded Secrets**: `process.env.SECRET = "abc123"` in code

## Known False-Positive Signatures

### Safe Patterns (DO NOT REPORT)
- **Cryptographically Secure RNG**: `secrets.token_hex()`, `crypto.getRandomValues()`, `crypto/rand`
- **Modern Hashing**: `bcrypt`, `argon2`, `scrypt`, `PBKDF2` for passwords
- **Strong Encryption**: `AES-GCM`, `AES-256-CBC` with HMAC, `ChaCha20-Poly1305`
- **Key Derivation**: `bcrypt.gensalt()`, `argon2.hash()`, `pbkdf2_derive()`
- **Proper TLS**: Valid certificate verification, strong cipher suites

## Bypass Detection Patterns

### Weak Crypto Exploitation
- **Hash Collisions**: MD5 collision attacks for certificate forgery
- **Rainbow Tables**: Unsalted hashes vulnerable to precomputation
- **Timing Attacks**: Non-constant-time string comparison for tokens
- **Padding Oracle**: CBC padding oracle attacks
- **Key Recovery**: Brute-force weak keys, default credentials

### Implementation Flaws
- **ECB Mode**: Patterns visible in encrypted data
- **IV Reuse**: Same IV used multiple times with same key
- **Short Keys**: Keys shorter than 128 bits
- **Predictable Nonces**: Nonce reuse in stream ciphers

## Chain Opportunities

### Crypto Vulnerabilities Enable
- **Credential Theft**: Cracking weak password hashes
- **Session Hijacking**: Predicting session tokens from weak RNG
- **Data Decryption**: Breaking weak encryption schemes
- **Certificate Forgery**: MD5 collision for fake certificates
- **Authentication Bypass**: Timing attacks on token comparison

### Priority Indicators
- **Critical**: Hardcoded encryption keys, weak RNG for tokens/passwords
- **High**: MD5/SHA1 for passwords, ECB mode encryption, InsecureSkipVerify
- **Medium**: Missing rate limiting on auth, weak password policies
- **Low**: Outdated TLS versions (1.0/1.1), missing HSTS headers