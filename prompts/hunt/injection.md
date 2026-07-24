# Injection Vulnerability Hunt Guide

## Dangerous API Patterns by Language

### C/C++
- **Command Injection**: `system()`, `popen()`, `exec*()`, `spawn*()` with user input
- **SQL**: Direct string concatenation into SQL queries (rare in C, more common in embedded)
- **Format String**: `printf(user_input)`, `sprintf(buf, user_controlled_format)`
- **LDAP**: Custom implementations using string building for LDAP filters

### Python
- **SQL**: `"SELECT * FROM users WHERE id=" + user_id`, `cursor.execute(f"SELECT * FROM {table}")`
- **Command**: `os.system("ping " + ip)`, `subprocess.call("ls " + path, shell=True)`
- **SSTI**: `render_template_string(user_input)`, `format(user_input)`
- **Code Execution**: `eval(user_input)`, `exec(user_input)`, `compile()`

### Java
- **SQL**: `Statement.executeQuery("SELECT * FROM users WHERE id=" + id)`
- **Command**: `Runtime.getRuntime().exec("ping " + host)`, `ProcessBuilder` with user input
- **LDAP**: `context.search(filter)` with unsanitized filter strings
- **XXE**: `DocumentBuilder.parse()` with external entity resolution enabled

### Go
- **SQL**: `db.Query("SELECT * FROM users WHERE id=" + id)`, `fmt.Sprintf(query, user_input)`
- **Command**: `exec.Command("sh", "-c", "ping "+host)`
- **Template Injection**: `template.HTML(user_input)`, `tmpl.ExecuteTemplate()` with user templates

### JavaScript/Node.js
- **SQL**: `query("SELECT * FROM users WHERE id=" + id)`
- **NoSQL**: `find({$where: "this.name == " + user_input})`
- **Command**: `exec("ping " + host)`, `spawn("sh", ["-c", cmd])`
- **Prototype Pollution**: `Object.assign(target, user_input)`

## Known False-Positive Signatures

### Safe Patterns (DO NOT REPORT)
- **Parameterized Queries**: `cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))`
- **Prepared Statements**: `PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id=?")`
- **ORM Methods**: `User.objects.get(id=user_id)`, `db.users.find({id: userId})`
- **Escaping Functions**: `mysql_real_escape_string()`, `pg_escape_literal()`
- **Whitelist Validation**: Input validated against known-good patterns before use

## Bypass Detection Patterns

### Encoding Tricks
- URL encoding: `%27` for `'`, `%22` for `"`
- Double encoding: `%2527` → `%27` → `'`
- Unicode encoding: `\u0027` for `'`
- Hex encoding: `0x27` for `'`

### Comment Injection
- SQL comments: `--`, `#`, `/* */`
- Null bytes: `%00`, `\0` in path traversal
- Line breaks: `%0a`, `%0d` to bypass filters

### Concatenation Attacks
- String concatenation to evade filters: `' OR '1'='1`
- Type confusion: `1 OR 1=1` in numeric context

## Chain Opportunities

### Injection Enables
- **Authentication Bypass**: SQLi can bypass login forms
- **Command Execution**: SQLi with `xp_cmdshell` (SQL Server) or `INTO OUTFILE` (MySQL)
- **XSS**: Stored XSS via database injection
- **Path Traversal**: Command injection can read arbitrary files
- **SSRF**: Command injection can make internal network requests

### Priority Indicators
- **Critical**: Database credentials in connection strings, admin panel access
- **High**: User input directly in system commands, authentication queries
- **Medium**: Read-only database queries, non-critical command output
- **Low**: Logged-only user input, debug endpoints