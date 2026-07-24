# Authentication/Authorization Vulnerability Hunt Guide

## Dangerous API Patterns by Language

### C/C++
- **Password Storage**: `MD5(password)`, `SHA1(password)` without salt
- **Session Management**: Hardcoded session keys, predictable session IDs
- **Access Control**: Missing permission checks before file operations
- **Buffer Overflows in Auth**: `strcpy` in password comparison buffers

### Python
- **Password Hashing**: `hashlib.md5(password)`, `hashlib.sha1(password)`
- **Session Tokens**: `secrets.token_hex()` without proper entropy, hardcoded secrets
- **Auth Bypass**: `if user == 'admin':` without proper validation
- **JWT**: `jwt.decode(token, verify=False)`, weak JWT algorithms (none, HS256 with weak secret)

### Java
- **Password Hashing**: `MessageDigest.getInstance("MD5")`, `SHA-1`
- **Session**: `session.setAttribute()` without timeout, predictable session IDs
- **Authorization**: `request.isUserInRole()` not called, missing `@PreAuthorize`
- **Hardcoded Secrets**: `String apiKey = "abc123";`, `private static final String SECRET = "..."`

### Go
- **Password Hashing**: `sha256.Sum256(password)` without bcrypt/argon2
- **JWT**: `Parse(token, func(...) { return nil })` skipping signature verification
- **Session**: Hardcoded session secrets, missing CSRF tokens
- **Auth Middleware**: Empty middleware functions, missing permission checks

### JavaScript/Node.js
- **Password Hashing**: `crypto.createHash('md5').update(password)`
- **JWT**: `jwt.verify(token, secret, { algorithms: ['none'] })`
- **Session**: `express-session` without `secure: true`, `httpOnly: true`
- **Auth Logic**: `if (req.query.admin === 'true')`, missing role checks

## Known False-Positive Signatures

### Safe Patterns (DO NOT REPORT)
- **Proper Password Hashing**: `bcrypt.hash(password, saltRounds)`, `argon2.hash(password)`
- **JWT Verification**: `jwt.verify(token, secret, { algorithms: ['RS256'] })` with proper validation
- **Session Security**: `secure: true, httpOnly: true, sameSite: 'strict'`
- **Role-Based Access**: `@RequiresRoles("ADMIN")`, `if (user.role === 'admin' && user.verified)`
- **OAuth/OIDC**: Proper implementation using established libraries (passport.js, oauth2-server)

## Bypass Detection Patterns

### Authentication Bypass
- **Parameter Pollution**: `?admin=true&admin=false`
- **Type Juggling**: `if (userId == "1")` in PHP/JS
- **HTTP Parameter Pollution**: Duplicate parameters to confuse logic
- **Null Byte Injection**: `admin.txt%00.jpg` to bypass extensions
- **Race Conditions**: Concurrent requests to bypass rate limiting

### Authorization Bypass
- **IDOR**: `GET /api/users/1` → `GET /api/users/2` without ownership check
- **Privilege Escalation**: Modifying role claims in JWT, URL parameter tampering
- **Missing Middleware**: Protected routes without auth middleware
- **CORS Misconfiguration**: `Access-Control-Allow-Origin: *` on auth endpoints

## Chain Opportunities

### Auth Vulnerabilities Enable
- **Data Breach**: Unauthorized access to sensitive data
- **Privilege Escalation**: Admin access leads to RCE or full system compromise
- **Account Takeover**: Session fixation, weak password policies
- **Business Logic Abuse**: Bypass payment, free access to premium features
- **Lateral Movement**: Compromised credentials used for internal network access

### Priority Indicators
- **Critical**: Admin authentication bypass, password reset flaws, MFA bypass
- **High**: IDOR on sensitive data, JWT validation flaws, session fixation
- **Medium**: Weak password policies, missing rate limiting, verbose error messages
- **Low**: Missing security headers, informational disclosure in error pages