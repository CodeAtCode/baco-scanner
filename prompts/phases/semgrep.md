# Semgrep Phase Prompt

Analyze code for security vulnerabilities using Semgrep patterns. Target directory: %%PROJECT_PATH%%

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
    "cwe_id": "CWE-787"
  }
]
