# Path Traversal/SSRF Vulnerability Hunt Guide

## Dangerous API Patterns by Language

### C/C++
- **File Operations**: `fopen(user_input)`, `open(user_input, O_RDONLY)`
- **Path Construction**: `sprintf(path, "/home/%s/file", username)`
- **Command with Paths**: `system("cat " + filepath)`
- **Missing Normalization**: No `realpath()` or `canonicalize()` before access

### Python
- **File Operations**: `open("/home/" + username + "/data.txt")`, `Path(user_input).read_text()`
- **Shutil**: `shutil.copy(user_file, dest)` without validation
- **Archive Extraction**: `zipfile.extractall()` without path validation
- **URL Fetching**: `urllib.request.urlopen(user_url)` for SSRF

### Java
- **File Operations**: `new FileInputStream(user_input)`, `Paths.get(user_input)`
- **NIO**: `Files.readAllBytes(Paths.get(user_input))`
- **URL Connection**: `new URL(userUrl).openStream()` for SSRF
- **Zip Slip**: `ZipEntry.getName()` without path validation

### Go
- **File Operations**: `os.Open(userInput)`, `ioutil.ReadFile(userInput)`
- **Path Join**: `filepath.Join(basePath, userInput)` without Clean()
- **HTTP Client**: `http.Get(userInput)` for SSRF
- **Archive**: `tar.Extract()` without path validation

### JavaScript/Node.js
- **File Operations**: `fs.readFileSync(userInput)`, `fs.readFile(userInput)`
- **Path Join**: `path.join(basePath, userInput)` without normalize()
- **HTTP**: `axios.get(userInput)`, `request(userInput)` for SSRF
- **Archive**: `adm-zip` extract without path validation

## Known False-Positive Signatures

### Safe Patterns (DO NOT REPORT)
- **Path Normalization**: `os.path.realpath()`, `filepath.Clean()`, `Path.resolve()`
- **Whitelist Validation**: File paths validated against allowed list
- **Chroot/Jail**: Operations confined to sandboxed directory
- **Parameterized File Access**: File access by ID, not path
- **SSRF Protection**: URL allowlist, internal IP blocking, scheme validation

## Bypass Detection Patterns

### Path Traversal Evasion
- **Double Encoding**: `%252f%252f` → `%2f%2f` → `//`
- **Unicode**: `..%u2215` (Unicode for `/`)
- **Null Bytes**: `file.txt%00.jpg` to bypass extension checks
- **Dot Tricks**: `....//` → `../` after filter removal
- **Mixed Separators**: `..\../..\\` on Windows

### SSRF Evasion
- **IP Encoding**: `0x7f000001` for `127.0.0.1`
- **Decimal IP**: `2130706433` for `127.0.0.1`
- **URL Obfuscation**: `http://127.1@external.com`
- **DNS Rebinding**: Rapid DNS changes to bypass allowlist
- **Protocol Tricks**: `file://`, `gopher://`, `dict://`

### Canonicalization Issues
- **Symlink Attacks**: Symlinks to sensitive files
- **Race Conditions**: TOCTOU in path validation
- **Network Paths**: `\\localhost\c$` on Windows

## Chain Opportunities

### Path Traversal Enables
- **Source Code Disclosure**: Reading `/etc/passwd`, `.git/config`
- **Configuration Theft**: Access to API keys, database credentials
- **RCE**: Overwriting webshells, SSH keys, cron jobs
- **Privilege Escalation**: Modifying `/etc/sudoers`, system configs

### SSRF Enables
- **Internal Network Recon**: Scanning internal ports, services
- **Cloud Metadata**: Accessing `http://169.254.169.254/` for credentials
- **Internal Admin Panels**: Accessing Redis, MongoDB, admin interfaces
- **Port Scanning**: Identifying internal services
- **Protocol Abuse**: `file://`, `gopher://` for internal attacks

### Priority Indicators
- **Critical**: SSRF to cloud metadata, path traversal to system files
- **High**: SSRF to internal services, path traversal to app configs
- **Medium**: SSRF with limited protocols, path traversal in non-sensitive dirs
- **Low**: SSRF with strict allowlist, path traversal with proper validation