//! Embedded default prompt templates for all BACO phases and project types.
//! These templates can be overridden via config.toml [phases.phase_name] sections.

use std::collections::HashMap;

/// All 11 BACO phases plus T2.5 six-phase orchestration
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum BacoPhase {
    Indexing,
    Semgrep,
    LlmStaticAnalysis,
    LlmDiscovery,
    LlmVerification,
    TicketCrossRef,
    GitAnalysis,
    CrossFileAnalysis,
    ConfidenceScoring,
    AiAggregation,
    Reporting,
    // T2.5 six-phase orchestration
    Hunt,
    Validate,
    IndependentVerify,
}

/// All project type categories
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectType {
    CLI,
    Web,
    Library,
    Embedded,
    Firmware,
    Desktop,
}

impl std::fmt::Display for BacoPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BacoPhase::Indexing => write!(f, "indexing"),
            BacoPhase::Semgrep => write!(f, "semgrep"),
            BacoPhase::LlmStaticAnalysis => write!(f, "llm_static_analysis"),
            BacoPhase::LlmDiscovery => write!(f, "llm_discovery"),
            BacoPhase::LlmVerification => write!(f, "llm_verification"),
            BacoPhase::TicketCrossRef => write!(f, "ticket_crossref"),
            BacoPhase::GitAnalysis => write!(f, "git_analysis"),
            BacoPhase::CrossFileAnalysis => write!(f, "cross_file_analysis"),
            BacoPhase::ConfidenceScoring => write!(f, "confidence_scoring"),
            BacoPhase::AiAggregation => write!(f, "ai_aggregation"),
            BacoPhase::Reporting => write!(f, "reporting"),
            // T2.5 six-phase orchestration
            BacoPhase::Hunt => write!(f, "hunt"),
            BacoPhase::Validate => write!(f, "validate"),
            BacoPhase::IndependentVerify => write!(f, "independent_verify"),
        }
    }
}

impl std::fmt::Display for ProjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProjectType::CLI => write!(f, "cli"),
            ProjectType::Web => write!(f, "web"),
            ProjectType::Library => write!(f, "library"),
            ProjectType::Embedded => write!(f, "embedded"),
            ProjectType::Firmware => write!(f, "firmware"),
            ProjectType::Desktop => write!(f, "desktop"),
        }
    }
}

/// Template metadata with required variables
#[derive(Debug, Clone)]
pub struct TemplateMeta {
    pub name: String,
    pub description: String,
    pub required_variables: Vec<String>,
}

/// Key-value pairs for template substitution
#[derive(Debug, Clone, Default)]
pub struct TemplateVariables(pub HashMap<String, String>);

impl TemplateVariables {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: String, value: String) {
        self.0.insert(key, value);
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Embedded default prompts for all BACO phases
///
/// These templates follow the format:
/// - {variable_name} placeholders for dynamic content
/// - %%VAR%% format for legacy compatibility
#[derive(Debug)]
pub struct DefaultPrompts {
    pub indexing: String,
    pub semgrep: String,
    pub llm_static_analysis: String,
    pub llm_discovery: String,
    pub llm_verification: String,
    pub ticket_crossref: String,
    pub git_analysis: String,
    pub cross_file_analysis: String,
    pub confidence_scoring: String,
    pub ai_aggregation: String,
    pub reporting: String,
}

impl Default for DefaultPrompts {
    fn default() -> Self {
        Self {
            indexing: Self::indexing_template(),
            semgrep: Self::semgrep_template(),
            llm_static_analysis: Self::llm_static_analysis_template(),
            llm_discovery: Self::llm_discovery_template(),
            llm_verification: Self::llm_verification_template(),
            ticket_crossref: Self::ticket_crossref_template(),
            git_analysis: Self::git_analysis_template(),
            cross_file_analysis: Self::cross_file_analysis_template(),
            confidence_scoring: Self::confidence_scoring_template(),
            ai_aggregation: Self::ai_aggregation_template(),
            reporting: Self::reporting_template(),
        }
    }
}

impl DefaultPrompts {
    fn indexing_template() -> String {
        r#"Analyze the project structure at %%PROJECT_PATH%%. Create a comprehensive index of all source code files. Consider:

- File extensions: %%FILE_EXTENSIONS%%
- Languages to index: %%LANGUAGES%%
- Maximum file size: %%MAX_FILE_SIZE%% bytes
- Exclude paths: %%EXCLUDE_PATHS%%

Output format: JSON array with file paths, sizes, and language detection.
Result: [
  {"path": "relative/path", "size": bytes, "language": "c/cpp/python"},
  ...
]
"#.to_string()
    }

    fn semgrep_template() -> String {
        r#"Analyze code for security vulnerabilities using Semgrep patterns. Target directory: %%PROJECT_PATH%%

Focus areas:
- Buffer overflows and memory safety issues
- SQL injection and command injection
- XSS and injection vulnerabilities
- Authentication bypass patterns
- Cryptographic weaknesses

Return JSON array with findings:
[
  {
    "file": "path/to/file",
    "line": line_number,
    "message": "vulnerability description",
    "severity": "critical|high|medium|low",
    "cwe_id": " CWE-787"
  }
]
"#.to_string()
    }

    fn llm_static_analysis_template() -> String {
        r#"Analyze this %%LANGUAGE%% code for security vulnerabilities.

Code location: %%FILE_PATH%%
Line numbers: %%LINE_RANGE%%
Context lines: %%CONTEXT_LINES%% (before and after)

Relevant CWE Specifications:
%%CWE_SPECS%%

Analyze for:
1. Memory safety issues (buffer overflows, use-after-free)
2. Input validation gaps (XSS, SQL injection, command injection)
3. Authentication/authorization weaknesses
4. Cryptographic weaknesses
5. Configuration errors
6. Race conditions

Return JSON array with format:
[
  {
    "severity": "critical|high|medium|low",
    "title": "short vulnerable code title",
    "description": "detailed vulnerability explanation",
    "line": line_number,
    "statement_range": [start_line, end_line] - OPTIONAL: inclusive range of vulnerable statements, omit for function-level only
    "cwe_id": "MUST BE ONE OF: CWE-22 (path traversal), CWE-79 (XSS), CWE-89 (SQL injection), CWE-94 (code injection), CWE-476 (NULL pointer), CWE-611 (XXE), CWE-798 (hardcoded credentials)",
    "fix_code": "SECURE version of the vulnerable code - show how the code SHOULD be written",
    "recommendation": "fix suggestion"
  }
]

STRICT REQUIREMENTS: 
- cwe_id field MUST be a valid CWE number like CWE-611, CWE-79, CWE-22, etc.
- fix_code MUST be the corrected code, NOT continuation of the original code

IMPORTANT: Include context for better analysis.
Code:
```%%LANG%%
%%CODE_CONTENT%%
```
"#
        .to_string()
    }

    fn llm_discovery_template() -> String {
        r#"Enrich the following security vulnerability finding with detailed context and explanation.

Finding: %%FINDING_TITLE%%
Location: %%FILE_PATH%%:%%LINE_NUMBER%%
Current description: %%CURRENT_DESCRIPTION%%

Enhancement goals:
1. Add technical depth to the explanation
2. Include potential attack scenarios
3. Suggest specific remediation steps
4. Mention related CWE categories
5. Provide code examples of fixes

Return ONLY the enriched description as plain text.
Format:
- Technical explanation (what's wrong)
- Attack scenario (how it could be exploited)
- Remediation (how to fix it)
- Related CWEs (if applicable)
"#.to_string()
    }

    fn llm_verification_template() -> String {
        r#"Verify if this security vulnerability finding is a true positive, false positive, or needs review.

Finding: %%FINDING_TITLE%%
Location: %%FILE_PATH%%:%%LINE_NUMBER%%
Description: %%VULNERABILITY_DESCRIPTION%%
Sources: %%SOURCE_LIST%%

Analysis criteria:
- Is the vulnerable code actually exploitable?
- Are there mitigating factors (sanitization, sandboxing)?
- Is this a known false positive pattern?
- Does the code actually execute at runtime?

Return JSON with format:
{
  "verification_status": "confirmed|false_positive|needs_review",
  "verification_notes": "detailed reasoning",
  "confidence": 0.0-1.0,
  "mitigating_factors": ["optional mitigation 1", ...],
  "related_patterns": ["optional pattern 1", ...]
}
"#.to_string()
    }

    fn ticket_crossref_template() -> String {
        r#"Search for this vulnerability in ticket systems and correlate with existing issues.

Vulnerability title: %%VULNERABILITY_TITLE%%
File path: %%FILE_PATH%%
Description: %%VULNERABILITY_DESCRIPTION%%

Search strategies:
1. Search ticket IDs by vulnerability title keywords
2. Search by file path in commit history
3. Search by CWE classification
4. Search by affected function names

Ticket systems to search:
- %%TICKET_SYSTEMS%% (GitHub, GitLab, Jira, etc.)

Return JSON array with matches:
[
  {
    "system": "github|gitlab|jira|custom",
    "ticket_id": "TICKET-123",
    "title": "related ticket title",
    "url": "https://example.com/issue/123",
    "confidence": 0.0-1.0
  }
]

Note: Return empty array [] if no matches found.
"#
        .to_string()
    }

    fn git_analysis_template() -> String {
        r#"Analyze Git history for the specified file to understand vulnerability evolution.

File path: %%FILE_PATH%%
Line number: %%LINE_NUMBER%% (if known, else analyze entire file)

Analysis tasks:
1. Find commits that introduced the suspicious code pattern
2. Track evolution of the vulnerable function
3. Identify related security improvements
4. Note author commit history on this file

Git commands to run:
- git log --follow -- %%FILE_PATH%%
- git blame %%FILE_PATH%%
- git log -p -- %%FILE_PATH%% (context around line)

Return JSON array with commits:
[
  {
    "commit_hash": "abc123def",
    "author": "Author Name",
    "date": "2024-01-15T10:30:00Z",
    "message": "commit message",
    "role": "introduced|modified|reviewed|security_related"
  }
]
"#
        .to_string()
    }

    fn cross_file_analysis_template() -> String {
        r#"Analyze cross-file references and data flow to understand vulnerability propagation.

Input vulnerabilities:
%%VULNERABILITY_LIST%% (JSON array of finding objects)

Analysis tasks:
1. Identify shared functions that process vulnerable data
2. Trace data flow from vulnerable entry points to dangerous sinks
3. Find common patterns across multiple files
4. Detect potential RCE via inclusion chains

Return JSON array with cross-references:
[
  {
    "source_file": "a/b/c.c",
    "target_file": "x/y/z.c",
    "connection_type": "shared_function|data_flow|include_dependency",
    "explanation": "how they are related",
    "risk_increase": "low|medium|high"
  }
]
"#
        .to_string()
    }

    fn confidence_scoring_template() -> String {
        r#"Recalculate confidence scores for security vulnerability findings.

For each finding, consider:
1. Evidence quality:
   - Static analysis (Semgrep): moderate confidence
   - LLM analysis: low-to-moderate (needs verification)
   - Verified by human: high confidence
   - Confirmed false positive: 0.0

2. Source reliability:
   - Multiple independent sources: higher confidence
   - Single source: lower confidence

3. Mitigating factors:
   - Presence of sanitization: reduces confidence
   - Use in non-critical code path: reduces confidence
   - Known false positive pattern: low confidence

Input findings: %%FINDINGS_LIST%%

Return JSON array with recalculated scores:
[
  {
    "id": "unique-finding-id",
    "original_score": 0.0-1.0,
    "recalculated_score": 0.0-1.0,
    "evidence_sources": ["semgrep", "llm_analysis"],
    "adjustment_reason": "reason for score change"
  }
]
"#
        .to_string()
    }

    fn ai_aggregation_template() -> String {
        r#"Aggregate security findings into an executive summary and risk assessment.

Input: %%FINDINGS_LIST%% (JSON array of all vulnerabilities)
Project type: %%PROJECT_TYPE%%
Languages: %%LANGUAGES%%
Total files: %%TOTAL_FILES%%
Scan date: %%SCAN_DATE%%

Generate:
1. Executive Summary:
   - Total vulnerabilities by severity
   - Critical findings requiring immediate attention
   - Most affected components/modules

2. Risk Assessment:
   - Overall risk level: critical|high|medium|low
   - Attack surface analysis
   - Remediation priority ranking

3. Recommendations:
   - Immediate fixes (critical/high severity)
   - Long-term improvements
   - Security testing recommendations

Return JSON:
{
  "executive_summary": "100 word summary...",
  "risk_level": "high",
  "total_vulnerabilities": 42,
  "by_severity": {
    "critical": 2,
    "high": 8,
    "medium": 15,
    "low": 17
  },
  "critical_findings": [
    {
      "title": "...",
      "file": "...",
      "line": 123,
      "severity": "critical",
      "business_impact": "..."
    }
  ],
  "remediation_priority": [
    {"order": 1, "title": "...", "effort": "low|medium|high"},
    ...
  ],
  "recommendations": ["recommendation 1", "recommendation 2", ...]
}
"#
        .to_string()
    }

    fn reporting_template() -> String {
        r#"Generate security scan report for %%PROJECT_NAME%%.

Scan metadata:
- Date: %%SCAN_DATE%%
- Scanned files: %%FILES_COUNT%%
- Total vulnerabilities found: %%TOTAL_FINDINGS%%
- Tools used: %%TOOLS_USED%%
- Scan duration: %%SCAN_DURATION%%

Report sections to include:
1. Executive Summary (for management)
2. Critical Findings (detailed with remediation)
3. Security Recommendations
4. Appendix: All findings with JSON data

Output formats:
- JSON: Structured data for API consumption
- HTML: Human-readable report with styling
- SARIF: Standard format for CI/CD integration

Report requirements:
- Clear severity indicators
- Actionable remediation steps
- Reference to CWE IDs
- File locations with line numbers
- Confidence scores

Generate report content in the specified format.
"#
        .to_string()
    }
}

/// Get default prompt for a phase, applying project type customization
pub fn get_default_prompt(phase: &BacoPhase, _project_type: &ProjectType) -> String {
    let defaults = DefaultPrompts::default();
    match phase {
        BacoPhase::Indexing => defaults.indexing,
        BacoPhase::Semgrep => defaults.semgrep,
        BacoPhase::LlmStaticAnalysis => defaults.llm_static_analysis,
        BacoPhase::LlmDiscovery => defaults.llm_discovery,
        BacoPhase::LlmVerification => defaults.llm_verification,
        BacoPhase::TicketCrossRef => defaults.ticket_crossref,
        BacoPhase::GitAnalysis => defaults.git_analysis,
        BacoPhase::CrossFileAnalysis => defaults.cross_file_analysis,
        BacoPhase::ConfidenceScoring => defaults.confidence_scoring,
        BacoPhase::AiAggregation => defaults.ai_aggregation,
        BacoPhase::Reporting => defaults.reporting,
        // T2.5 six-phase orchestration - use generic prompts
        BacoPhase::Hunt => defaults.llm_discovery,
        BacoPhase::Validate => defaults.llm_verification,
        BacoPhase::IndependentVerify => defaults.llm_discovery,
    }
}

/// Get all default prompts
pub fn get_all_defaults() -> DefaultPrompts {
    DefaultPrompts::default()
}

// ============================================================================
// T2.5 Six-Phase Hunt Templates (Cloudflare pattern)
// ============================================================================

/// Injection hunt prompt (SQL, command, LDAP)
pub fn injection_hunt_prompt(source: &str) -> String {
    format!(
        r#"HUNT FOR INJECTION VULNERABILITIES ONLY.

Attack class: Injection (SQL injection, command injection, LDAP injection, format strings)
Task: Analyze this code and report ONLY injection vulnerabilities.

DANGEROUS APIs BY LANGUAGE:
- C/C++: system(), popen(), exec*(), sprintf() with user input, printf(user_input)
- Python: os.system(), subprocess.call(shell=True), eval(), exec(), render_template_string()
- Java: Statement.executeQuery() with concatenation, Runtime.exec(), context.search()
- Go: db.Query() with Sprintf, exec.Command("sh", "-c"), template.HTML()
- Node.js: exec(), spawn("sh", "-c"), query() with concatenation, innerHTML

SAFE PATTERNS (DO NOT REPORT):
- Parameterized queries: cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
- Prepared statements: PreparedStatement with ? placeholders
- ORM methods: User.objects.get(id=user_id), db.users.find({{id: userId}})
- Proper escaping: htmlspecialchars(), mysql_real_escape_string()

BYPASS DETECTION PATTERNS:
- Encoding: %27 for ', %22 for ", double encoding %2527
- Comments: --, #, /* */ in SQL, null bytes %00
- Concatenation: ' OR '1'='1, type confusion 1 OR 1=1

CHAIN OPPORTUNITIES:
- SQLi → Auth bypass, command execution via xp_cmdshell
- Command injection → File read, SSRF, lateral movement
- Stored injection → XSS, data exfiltration

Return JSON array with format:
[
  {{
    "severity": "critical|high|medium|low",
    "title": "injection vulnerability title",
    "description": "detailed explanation of the injection flaw",
    "line": line_number,
    "cwe_id": "CWE-XXX",
    "confidence": 0.0-1.0
  }}
]

CRITICAL: ONLY report injection vulnerabilities. Ignore all other attack classes.

Code:
```
{}
```"#,
        source
    )
}

/// Authentication/Authorization hunt prompt
pub fn auth_hunt_prompt(source: &str) -> String {
    format!(
        r#"HUNT FOR AUTHENTICATION/AUTHORIZATION VULNERABILITIES ONLY.

Attack class: Authentication/Authorization (bypass, privilege escalation, session flaws)
Task: Analyze this code and report ONLY auth-related vulnerabilities.

DANGEROUS APIs BY LANGUAGE:
- C/C++: MD5(password), hardcoded session keys, missing permission checks
- Python: hashlib.md5/sha1(password), jwt.decode(token, verify=False), secrets.token_hex() without entropy
- Java: MessageDigest.getInstance("MD5"), session.setAttribute() without timeout, missing @PreAuthorize
- Go: sha256.Sum256(password) without bcrypt, jwt.Parse with nil key function
- Node.js: crypto.createHash('md5'), jwt.verify with algorithms: ['none'], missing role checks

SAFE PATTERNS (DO NOT REPORT):
- Proper hashing: bcrypt.hash(), argon2.hash(), PBKDF2
- JWT verification: jwt.verify(token, secret, {{algorithms: ['RS256']}})
- Session security: secure:true, httpOnly:true, sameSite:'strict'
- RBAC: @RequiresRoles(), if (user.role === 'admin' && user.verified)

BYPASS DETECTION PATTERNS:
- Parameter pollution: ?admin=true&admin=false
- Type juggling: if (userId == "1") in PHP/JS
- IDOR: GET /api/users/1 → GET /api/users/2 without ownership check
- HTTP verb tampering: POST → GET/PUT/DELETE
- Race conditions: Concurrent requests bypassing rate limits

CHAIN OPPORTUNITIES:
- Auth bypass → Full system access, data breach
- IDOR → Sensitive data exposure, account takeover
- Session flaws → Session hijacking, CSRF
- Privilege escalation → Admin access, RCE

Return JSON array with format:
[
  {{
    "severity": "critical|high|medium|low",
    "title": "auth vulnerability title",
    "description": "detailed explanation of the auth flaw",
    "line": line_number,
    "cwe_id": "CWE-XXX",
    "confidence": 0.0-1.0
  }}
]

CRITICAL: ONLY report authentication/authorization vulnerabilities. Ignore all other attack classes.

Code:
```
{}
```"#,
        source
    )
}

/// XSS hunt prompt
pub fn xss_hunt_prompt(source: &str) -> String {
    format!(
        r#"HUNT FOR XSS VULNERABILITIES ONLY.

Attack class: Cross-Site Scripting (reflected, stored, DOM-based)
Task: Analyze this code and report ONLY XSS vulnerabilities.

DANGEROUS APIs BY LANGUAGE:
- C/C++: printf("<div>%s</div>", user_input), custom templates without auto-escape
- Python: render_template_string(user_input), Markup(user_input), print(f"<p>{{user_input}}</p>")
- Java: <%= request.getParameter("q") %>, response.getWriter().println("<div>" + input)
- Go: tmpl.ExecuteTemplate() with user HTML, template.HTML(userInput), fmt.Fprintf(w, "<div>%s</div>", input)
- Node.js: element.innerHTML = userInput, document.write(), dangerouslySetInnerHTML, .html(userInput)

SAFE PATTERNS (DO NOT REPORT):
- Auto-escaping: Go html/template, Django templates with default auto-escape
- Proper encoding: htmlspecialchars(), escapeHtml(), textContent instead of innerHTML
- CSP: default-src 'self' headers
- React: Using children prop instead of dangerouslySetInnerHTML
- Sanitization: DOMPurify.sanitize(), bleach.clean()

BYPASS DETECTION PATTERNS:
- HTML entities: &#60;script&#62;
- Unicode: \u003cscript\u003e
- Case variation: <ScRiPt>
- Event handlers: <img src=x onerror=alert(1)>
- Context escape: "><script>alert(1)</script> in attribute context

CHAIN OPPORTUNITIES:
- XSS → Cookie theft, session hijacking
- DOM XSS → Keylogging, phishing
- Stored XSS → Malware delivery, reconnaissance
- XSS + CSRF → Authenticated action execution

Return JSON array with format:
[
  {{
    "severity": "critical|high|medium|low",
    "title": "XSS vulnerability title",
    "description": "detailed explanation of the XSS flaw",
    "line": line_number,
    "cwe_id": "CWE-79",
    "confidence": 0.0-1.0
  }}
]

CRITICAL: ONLY report XSS vulnerabilities. Ignore all other attack classes.

Code:
```
{}
```"#,
        source
    )
}

/// Path traversal/SSRF hunt prompt
pub fn path_traversal_hunt_prompt(source: &str) -> String {
    format!(
        r#"HUNT FOR PATH TRAVERSAL/SSRF VULNERABILITIES ONLY.

Attack class: Path Traversal / Server-Side Request Forgery
Task: Analyze this code and report ONLY path traversal or SSRF vulnerabilities.

DANGEROUS APIs BY LANGUAGE:
- C/C++: fopen(user_input), open(user_input), sprintf(path, "/home/%s/file", username)
- Python: open("/home/" + username), Path(user_input).read_text(), urllib.request.urlopen(user_url)
- Java: new FileInputStream(user_input), Paths.get(user_input), new URL(userUrl).openStream()
- Go: os.Open(userInput), filepath.Join(basePath, userInput) without Clean(), http.Get(userInput)
- Node.js: fs.readFileSync(userInput), path.join(basePath, userInput), axios.get(userInput)

SAFE PATTERNS (DO NOT REPORT):
- Path normalization: os.path.realpath(), filepath.Clean(), Path.resolve()
- Whitelist validation: File paths validated against allowed list
- Chroot/jail: Operations confined to sandboxed directory
- SSRF protection: URL allowlist, internal IP blocking, scheme validation

BYPASS DETECTION PATTERNS:
- Double encoding: %252f%252f → %2f%2f → //
- Unicode: ..%u2215 (Unicode for /)
- Null bytes: file.txt%00.jpg
- Dot tricks: ....// → ../ after filter removal
- IP obfuscation: 0x7f00001, 2130706433 for 127.0.0.1
- URL tricks: http://127.1@external.com

CHAIN OPPORTUNITIES:
- Path traversal → Source code disclosure, config theft, RCE via file overwrite
- SSRF → Internal network recon, cloud metadata access (169.254.169.254)
- SSRF → Internal admin panels (Redis, MongoDB), port scanning
- Symlink attacks → Sensitive file access

Return JSON array with format:
[
  {{
    "severity": "critical|high|medium|low",
    "title": "path traversal/SSRF vulnerability title",
    "description": "detailed explanation of the flaw",
    "line": line_number,
    "cwe_id": "CWE-22",
    "confidence": 0.0-1.0
  }}
]

CRITICAL: ONLY report path traversal or SSRF vulnerabilities. Ignore all other attack classes.

Code:
```
{}
```"#,
        source
    )
}

/// Cryptographic weakness hunt prompt
pub fn crypto_hunt_prompt(source: &str) -> String {
    format!(
        r#"HUNT FOR CRYPTOGRAPHIC VULNERABILITIES ONLY.

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
  {{
    "severity": "critical|high|medium|low",
    "title": "crypto vulnerability title",
    "description": "detailed explanation of the crypto flaw",
    "line": line_number,
    "cwe_id": "CWE-XXX",
    "confidence": 0.0-1.0
  }}
]

CRITICAL: ONLY report cryptographic vulnerabilities. Ignore all other attack classes.

Code:
```
{}
```"#,
        source
    )
}

/// Resource handling hunt prompt
pub fn resource_hunt_prompt(source: &str) -> String {
    format!(
        r#"HUNT FOR RESOURCE HANDLING VULNERABILITIES ONLY.

Attack class: Resource Handling (memory safety, integer overflow, DoS)
Task: Analyze this code and report ONLY resource handling vulnerabilities.

DANGEROUS APIs BY LANGUAGE:
- C/C++: malloc(size*count) without overflow check, strcpy/strcat/sprintf without bounds, large stack allocations
- Python: Unbounded list.append(), io.BytesIO() with large data, subprocess.call() blocking, json.loads() massive payloads
- Java: ArrayList.add() without bounds, unbounded thread creation, FileInputStream without try-with-resources, ReDoS in Pattern.compile()
- Go: make([]byte, userControlledSize), go func() without limits, ioutil.ReadAll() unbounded, deep recursion
- Node.js: Unbounded array push, Buffer.alloc(userSize), sync blocking operations, ReDoS in regex.test()

SAFE PATTERNS (DO NOT REPORT):
- Bounded allocation: Size validation before malloc, max limits on collections
- Context cancellation: context.WithTimeout(), signal.NotifyContext()
- Resource pools: Connection pools, thread pools with limits
- Try-with-resources: Python with open(), Java try-with-resources
- Rate limiting: Request throttling, queue limits

BYPASS DETECTION PATTERNS:
- Integer overflow: size*count wrapping, signed to unsigned conversion
- Memory exhaustion: Large JSON payloads, deeply nested structures
- CPU exhaustion: ReDoS patterns ^(a+)+$, infinite loops
- File descriptor leaks: Opening many files without closing
- Goroutine/thread leaks: Creating many concurrent workers

CHAIN OPPORTUNITIES:
- DoS → Service unavailability, crash exploitation
- Integer overflow → Buffer overflow, crash exploits
- Use-after-free → Information leak, code execution
- Race conditions → Privilege escalation, file operation bypass

Return JSON array with format:
[
  {{
    "severity": "critical|high|medium|low",
    "title": "resource handling vulnerability title",
    "description": "detailed explanation of the flaw",
    "line": line_number,
    "cwe_id": "CWE-XXX",
    "confidence": 0.0-1.0
  }}
]

CRITICAL: ONLY report resource handling vulnerabilities. Ignore all other attack classes.

Code:
```
{}
```"#,
        source
    )
}

/// Deserialization/config hunt prompt
pub fn deserialization_hunt_prompt(source: &str) -> String {
    format!(
        r#"HUNT FOR INSECURE DESERIALIZATION/CONFIG VULNERABILITIES ONLY.

Attack class: Insecure Deserialization / Configuration
Task: Analyze this code and report ONLY deserialization or config vulnerabilities.

DANGEROUS APIs BY LANGUAGE:
- C/C++: memcpy() from network without validation, read(fd, &struct) from untrusted source
- Python: pickle.loads(user_input), yaml.load(user_input) without SafeLoader, marshal.loads()
- Java: ObjectInputStream.readObject() from untrusted, xstream.fromXML() without allowlist, Jackson with polymorphic types
- Go: gob.NewDecoder().Decode() with untrusted data, json.Unmarshal() with interface{{}}
- Node.js: JSON.parse() with __proto__ pollution, yaml.parse() without safe options, serialize-javascript without strict

SAFE PATTERNS (DO NOT REPORT):
- Safe loaders: yaml.safe_load(), yaml.load(..., SafeLoader)
- Type allowlists: xstream.allowTypesByWildcard(["com.example.safe.*"])
- Schema validation: JSON Schema validation before parsing
- Immutable types: Deserializing only to immutable data structures
- JSON only: Using JSON instead of binary serialization formats

BYPASS DETECTION PATTERNS:
- Gadget chains: Apache Commons, Java Serialization RCE chains
- Type confusion: Casting to unexpected types after deserialization
- Prototype pollution: {{"__proto__": {{"admin": true}}}}
- Polymorphic abuse: Deserializing to unexpected subclasses
- Config issues: Hardcoded secrets, DEBUG=True, weak CORS, chmod 777

CHAIN OPPORTUNITIES:
- RCE via gadgets → Full system compromise, lateral movement
- Auth bypass → Deserializing admin session objects
- Privilege escalation → Modifying serialized permission objects
- Data tampering → Altering business logic state
- Config exposure → Credential theft, reconnaissance

Return JSON array with format:
[
  {{
    "severity": "critical|high|medium|low",
    "title": "deserialization/config vulnerability title",
    "description": "detailed explanation of the flaw",
    "line": line_number,
    "cwe_id": "CWE-XXX",
    "confidence": 0.0-1.0
  }}
]

CRITICAL: ONLY report deserialization or configuration vulnerabilities. Ignore all other attack classes.

Code:
```
{}
```"#,
        source
    )
}

/// Render a template string by substituting {{VAR}} placeholders with values from TemplateVariables
pub fn render_template(template: &str, variables: &TemplateVariables) -> String {
    let mut result = template.to_string();
    for (key, value) in &variables.0 {
        let placeholder_braces = format!("{{{{{}}}}}", key);
        let placeholder_percent = format!("%%{}%%", key);
        result = result.replace(&placeholder_braces, value);
        result = result.replace(&placeholder_percent, value);
    }
    result
}

/// Get all variable placeholders from a template string
pub fn get_template_variables(template: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let mut start = 0;
    while let Some(open_pos) = template[start..].find("{{") {
        let abs_open = start + open_pos;
        if let Some(close_pos) = template[abs_open + 2..].find("}}") {
            let abs_close = abs_open + 2 + close_pos;
            let var_name = &template[abs_open + 2..abs_close];
            if !vars.contains(&var_name.to_string()) {
                vars.push(var_name.to_string());
            }
            start = abs_close + 2;
        } else {
            break;
        }
    }
    start = 0;
    while let Some(open_pos) = template[start..].find("%%") {
        let abs_open = start + open_pos;
        if let Some(close_pos) = template[abs_open + 2..].find("%%") {
            let abs_close = abs_open + 2 + close_pos;
            let var_name = &template[abs_open + 2..abs_close];
            if !vars.contains(&var_name.to_string()) {
                vars.push(var_name.to_string());
            }
            start = abs_close + 2;
        } else {
            break;
        }
    }
    vars
}
