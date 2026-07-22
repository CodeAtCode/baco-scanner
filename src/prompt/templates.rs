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

Attack class: Injection (SQL injection, command injection, LDAP injection, etc.)
Task: Analyze this code and report ONLY injection vulnerabilities.

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

Attack class: Authentication/Authorization (bypass, privilege escalation, etc.)
Task: Analyze this code and report ONLY auth-related vulnerabilities.

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PromptSpec;

    // Test BacoPhase Display implementation
    #[test]
    fn test_baco_phase_display() {
        assert_eq!(BacoPhase::Indexing.to_string(), "indexing");
        assert_eq!(BacoPhase::Semgrep.to_string(), "semgrep");
        assert_eq!(
            BacoPhase::LlmStaticAnalysis.to_string(),
            "llm_static_analysis"
        );
        assert_eq!(BacoPhase::LlmDiscovery.to_string(), "llm_discovery");
        assert_eq!(BacoPhase::LlmVerification.to_string(), "llm_verification");
        assert_eq!(BacoPhase::TicketCrossRef.to_string(), "ticket_crossref");
        assert_eq!(BacoPhase::GitAnalysis.to_string(), "git_analysis");
        assert_eq!(
            BacoPhase::CrossFileAnalysis.to_string(),
            "cross_file_analysis"
        );
        assert_eq!(
            BacoPhase::ConfidenceScoring.to_string(),
            "confidence_scoring"
        );
        assert_eq!(BacoPhase::AiAggregation.to_string(), "ai_aggregation");
        assert_eq!(BacoPhase::Reporting.to_string(), "reporting");
    }

    // Test ProjectType Display implementation
    #[test]
    fn test_project_type_display() {
        assert_eq!(ProjectType::CLI.to_string(), "cli");
        assert_eq!(ProjectType::Web.to_string(), "web");
        assert_eq!(ProjectType::Library.to_string(), "library");
        assert_eq!(ProjectType::Embedded.to_string(), "embedded");
        assert_eq!(ProjectType::Firmware.to_string(), "firmware");
        assert_eq!(ProjectType::Desktop.to_string(), "desktop");
    }

    // Test TemplateVariables
    #[test]
    fn test_template_variables_new() {
        let vars = TemplateVariables::new();
        assert!(vars.is_empty());
        assert_eq!(vars.len(), 0);
    }

    #[test]
    fn test_template_variables_insert_and_get() {
        let mut vars = TemplateVariables::new();
        vars.insert("KEY1".to_string(), "value1".to_string());
        vars.insert("KEY2".to_string(), "value2".to_string());

        assert_eq!(vars.len(), 2);
        assert_eq!(vars.get("KEY1"), Some(&"value1".to_string()));
        assert_eq!(vars.get("KEY2"), Some(&"value2".to_string()));
        assert_eq!(vars.get("NONEXISTENT"), None);
    }

    #[test]
    fn test_template_variables_is_empty() {
        let mut vars = TemplateVariables::new();
        assert!(vars.is_empty());

        vars.insert("KEY".to_string(), "value".to_string());
        assert!(!vars.is_empty());
    }

    // Test DefaultPrompts all fields are non-empty
    #[test]
    fn test_default_prompts_all_fields_non_empty() {
        let prompts = get_all_defaults();

        assert!(!prompts.indexing.is_empty());
        assert!(!prompts.semgrep.is_empty());
        assert!(!prompts.llm_static_analysis.is_empty());
        assert!(!prompts.llm_discovery.is_empty());
        assert!(!prompts.llm_verification.is_empty());
        assert!(!prompts.ticket_crossref.is_empty());
        assert!(!prompts.git_analysis.is_empty());
        assert!(!prompts.cross_file_analysis.is_empty());
        assert!(!prompts.confidence_scoring.is_empty());
        assert!(!prompts.ai_aggregation.is_empty());
        assert!(!prompts.reporting.is_empty());
    }

    // Test get_default_prompt for all BacoPhase variants
    #[test]
    fn test_get_default_prompt_indexing() {
        let prompt = get_default_prompt(&BacoPhase::Indexing, &ProjectType::CLI);
        assert!(!prompt.is_empty());
        assert!(prompt.contains("%%PROJECT_PATH%%"));
        assert!(prompt.contains("%%FILE_EXTENSIONS%%"));
        assert!(prompt.contains("%%LANGUAGES%%"));
    }

    #[test]
    fn test_get_default_prompt_semgrep() {
        let prompt = get_default_prompt(&BacoPhase::Semgrep, &ProjectType::CLI);
        assert!(!prompt.is_empty());
        assert!(prompt.contains("%%PROJECT_PATH%%"));
        assert!(prompt.contains("security"));
        assert!(prompt.contains("vulnerabilities"));
    }

    #[test]
    fn test_get_default_prompt_llm_static_analysis() {
        let prompt = get_default_prompt(&BacoPhase::LlmStaticAnalysis, &ProjectType::CLI);
        assert!(!prompt.is_empty());
        assert!(prompt.contains("%%FILE_PATH%%"));
        assert!(prompt.contains("%%LINE_RANGE%%"));
        assert!(prompt.contains("%%CODE_CONTENT%%"));
        assert!(prompt.contains("CWE-"));
    }

    #[test]
    fn test_get_default_prompt_llm_discovery() {
        let prompt = get_default_prompt(&BacoPhase::LlmDiscovery, &ProjectType::CLI);
        assert!(!prompt.is_empty());
        assert!(prompt.contains("%%FINDING_TITLE%%"));
        assert!(prompt.contains("%%FILE_PATH%%"));
        assert!(prompt.contains("%%LINE_NUMBER%%"));
    }

    #[test]
    fn test_get_default_prompt_llm_verification() {
        let prompt = get_default_prompt(&BacoPhase::LlmVerification, &ProjectType::CLI);
        assert!(!prompt.is_empty());
        assert!(prompt.contains("%%FINDING_TITLE%%"));
        assert!(prompt.contains("%%FILE_PATH%%"));
        assert!(prompt.contains("true positive"));
        assert!(prompt.contains("false_positive"));
    }

    #[test]
    fn test_get_default_prompt_ticket_crossref() {
        let prompt = get_default_prompt(&BacoPhase::TicketCrossRef, &ProjectType::CLI);
        assert!(!prompt.is_empty());
        assert!(prompt.contains("%%VULNERABILITY_TITLE%%"));
        assert!(prompt.contains("%%FILE_PATH%%"));
        assert!(prompt.contains("%%TICKET_SYSTEMS%%"));
    }

    #[test]
    fn test_get_default_prompt_git_analysis() {
        let prompt = get_default_prompt(&BacoPhase::GitAnalysis, &ProjectType::CLI);
        assert!(!prompt.is_empty());
        assert!(prompt.contains("%%FILE_PATH%%"));
        assert!(prompt.contains("%%LINE_NUMBER%%"));
        assert!(prompt.contains("git log"));
        assert!(prompt.contains("git blame"));
    }

    #[test]
    fn test_get_default_prompt_cross_file_analysis() {
        let prompt = get_default_prompt(&BacoPhase::CrossFileAnalysis, &ProjectType::CLI);
        assert!(!prompt.is_empty());
        assert!(prompt.contains("%%VULNERABILITY_LIST%%"));
        assert!(prompt.contains("data flow"));
        assert!(prompt.contains("cross-file"));
    }

    #[test]
    fn test_get_default_prompt_confidence_scoring() {
        let prompt = get_default_prompt(&BacoPhase::ConfidenceScoring, &ProjectType::CLI);
        assert!(!prompt.is_empty());
        assert!(prompt.contains("%%FINDINGS_LIST%%"));
        assert!(prompt.contains("confidence"));
        assert!(prompt.contains("false positive"));
    }

    #[test]
    fn test_get_default_prompt_ai_aggregation() {
        let prompt = get_default_prompt(&BacoPhase::AiAggregation, &ProjectType::CLI);
        assert!(!prompt.is_empty());
        assert!(prompt.contains("%%FINDINGS_LIST%%"));
        assert!(prompt.contains("%%PROJECT_TYPE%%"));
        assert!(prompt.contains("executive summary"));
        assert!(prompt.contains("risk assessment"));
    }

    #[test]
    fn test_get_default_prompt_reporting() {
        let prompt = get_default_prompt(&BacoPhase::Reporting, &ProjectType::CLI);
        assert!(!prompt.is_empty());
        assert!(prompt.contains("%%PROJECT_NAME%%"));
        assert!(prompt.contains("%%SCAN_DATE%%"));
        assert!(prompt.contains("%%TOTAL_FINDINGS%%"));
        assert!(prompt.contains("SARIF"));
    }

    // Test that all phases return different prompts
    #[test]
    fn test_all_phases_return_different_prompts() {
        let prompts = get_all_defaults();

        let all_prompts = vec![
            &prompts.indexing,
            &prompts.semgrep,
            &prompts.llm_static_analysis,
            &prompts.llm_discovery,
            &prompts.llm_verification,
            &prompts.ticket_crossref,
            &prompts.git_analysis,
            &prompts.cross_file_analysis,
            &prompts.confidence_scoring,
            &prompts.ai_aggregation,
            &prompts.reporting,
        ];

        // Check all prompts are unique
        for i in 0..all_prompts.len() {
            for j in (i + 1)..all_prompts.len() {
                assert_ne!(
                    all_prompts[i], all_prompts[j],
                    "Prompts for phase {} and {} should be different",
                    i, j
                );
            }
        }
    }

    // Test DefaultPrompts derives Debug and Clone
    #[test]
    fn test_default_prompts_debug() {
        let prompts = get_all_defaults();
        let debug_output = format!("{:?}", prompts);
        assert!(debug_output.contains("indexing"));
        assert!(debug_output.contains("semgrep"));
    }

    // Test TemplateVariables with HashMap operations
    #[test]
    fn test_template_variables_multiple_inserts() {
        let mut vars = TemplateVariables::new();

        for i in 0..10 {
            vars.insert(format!("KEY_{}", i), format!("value_{}", i));
        }

        assert_eq!(vars.len(), 10);

        for i in 0..10 {
            assert_eq!(
                vars.get(&format!("KEY_{}", i)),
                Some(&format!("value_{}", i))
            );
        }
    }

    // Test prompt templates contain required variables
    #[test]
    fn test_indexing_template_variables() {
        let prompts = get_all_defaults();
        assert!(prompts.indexing.contains("%%PROJECT_PATH%%"));
        assert!(prompts.indexing.contains("%%FILE_EXTENSIONS%%"));
        assert!(prompts.indexing.contains("%%LANGUAGES%%"));
        assert!(prompts.indexing.contains("%%MAX_FILE_SIZE%%"));
        assert!(prompts.indexing.contains("%%EXCLUDE_PATHS%%"));
    }

    #[test]
    fn test_semgrep_template_variables() {
        let prompts = get_all_defaults();
        assert!(prompts.semgrep.contains("%%PROJECT_PATH%%"));
        assert!(prompts.semgrep.contains("Buffer overflow"));
        assert!(prompts.semgrep.contains("SQL injection"));
        assert!(prompts.semgrep.contains("XSS"));
    }

    #[test]
    fn test_llm_static_analysis_template_variables() {
        let prompts = get_all_defaults();
        assert!(prompts.llm_static_analysis.contains("%%LANGUAGE%%"));
        assert!(prompts.llm_static_analysis.contains("%%FILE_PATH%%"));
        assert!(prompts.llm_static_analysis.contains("%%LINE_RANGE%%"));
        assert!(prompts.llm_static_analysis.contains("%%CONTEXT_LINES%%"));
        assert!(prompts.llm_static_analysis.contains("%%CODE_CONTENT%%"));
        assert!(prompts.llm_static_analysis.contains("CWE-22"));
        assert!(prompts.llm_static_analysis.contains("CWE-79"));
        assert!(prompts.llm_static_analysis.contains("CWE-89"));
    }

    #[test]
    fn test_llm_discovery_template_variables() {
        let prompts = get_all_defaults();
        assert!(prompts.llm_discovery.contains("%%FINDING_TITLE%%"));
        assert!(prompts.llm_discovery.contains("%%FILE_PATH%%"));
        assert!(prompts.llm_discovery.contains("%%LINE_NUMBER%%"));
        assert!(prompts.llm_discovery.contains("%%CURRENT_DESCRIPTION%%"));
    }

    #[test]
    fn test_llm_verification_template_variables() {
        let prompts = get_all_defaults();
        assert!(prompts.llm_verification.contains("%%FINDING_TITLE%%"));
        assert!(prompts.llm_verification.contains("%%FILE_PATH%%"));
        assert!(prompts.llm_verification.contains("%%LINE_NUMBER%%"));
        assert!(prompts
            .llm_verification
            .contains("%%VULNERABILITY_DESCRIPTION%%"));
        assert!(prompts.llm_verification.contains("%%SOURCE_LIST%%"));
        assert!(prompts.llm_verification.contains("confirmed"));
        assert!(prompts.llm_verification.contains("false_positive"));
        assert!(prompts.llm_verification.contains("needs_review"));
    }

    #[test]
    fn test_ticket_crossref_template_variables() {
        let prompts = get_all_defaults();
        assert!(prompts.ticket_crossref.contains("%%VULNERABILITY_TITLE%%"));
        assert!(prompts.ticket_crossref.contains("%%FILE_PATH%%"));
        assert!(prompts
            .ticket_crossref
            .contains("%%VULNERABILITY_DESCRIPTION%%"));
        assert!(prompts.ticket_crossref.contains("%%TICKET_SYSTEMS%%"));
    }

    #[test]
    fn test_git_analysis_template_variables() {
        let prompts = get_all_defaults();
        assert!(prompts.git_analysis.contains("%%FILE_PATH%%"));
        assert!(prompts.git_analysis.contains("%%LINE_NUMBER%%"));
    }

    #[test]
    fn test_cross_file_analysis_template_variables() {
        let prompts = get_all_defaults();
        assert!(prompts
            .cross_file_analysis
            .contains("%%VULNERABILITY_LIST%%"));
    }

    #[test]
    fn test_confidence_scoring_template_variables() {
        let prompts = get_all_defaults();
        assert!(prompts.confidence_scoring.contains("%%FINDINGS_LIST%%"));
    }

    #[test]
    fn test_ai_aggregation_template_variables() {
        let prompts = get_all_defaults();
        assert!(prompts.ai_aggregation.contains("%%FINDINGS_LIST%%"));
        assert!(prompts.ai_aggregation.contains("%%PROJECT_TYPE%%"));
        assert!(prompts.ai_aggregation.contains("%%LANGUAGES%%"));
        assert!(prompts.ai_aggregation.contains("%%TOTAL_FILES%%"));
        assert!(prompts.ai_aggregation.contains("%%SCAN_DATE%%"));
    }

    #[test]
    fn test_reporting_template_variables() {
        let prompts = get_all_defaults();
        assert!(prompts.reporting.contains("%%PROJECT_NAME%%"));
        assert!(prompts.reporting.contains("%%SCAN_DATE%%"));
        assert!(prompts.reporting.contains("%%FILES_COUNT%%"));
        assert!(prompts.reporting.contains("%%TOTAL_FINDINGS%%"));
        assert!(prompts.reporting.contains("%%TOOLS_USED%%"));
        assert!(prompts.reporting.contains("%%SCAN_DURATION%%"));
    }

    // Test BacoPhase ordering
    #[test]
    fn test_baco_phase_ordering() {
        let phases = vec![
            BacoPhase::Indexing,
            BacoPhase::Semgrep,
            BacoPhase::LlmStaticAnalysis,
            BacoPhase::LlmDiscovery,
        ];

        let mut sorted = phases.clone();
        sorted.sort();

        assert_eq!(phases, sorted);
    }

    // Test ProjectType ordering
    #[test]
    fn test_project_type_ordering() {
        let types = vec![ProjectType::CLI, ProjectType::Web, ProjectType::Library];

        let mut sorted = types.clone();
        sorted.sort();

        assert_eq!(types, sorted);
    }

    // Test hunt prompt functions
    #[test]
    fn test_injection_hunt_prompt() {
        let source = "SELECT * FROM users WHERE id = $input";
        let prompt = injection_hunt_prompt(source);

        assert!(prompt.contains("INJECTION VULNERABILITIES"));
        assert!(prompt.contains(source));
        assert!(prompt.contains("CWE-XXX"));
    }

    #[test]
    fn test_auth_hunt_prompt() {
        let source = "if (user.isAdmin) { grantAccess() }";
        let prompt = auth_hunt_prompt(source);

        assert!(prompt.contains("AUTHENTICATION/AUTHORIZATION"));
        assert!(prompt.contains(source));
    }

    #[test]
    fn test_xss_hunt_prompt() {
        let source = "<div>{{ user_input }}</div>";
        let prompt = xss_hunt_prompt(source);

        assert!(prompt.contains("XSS VULNERABILITIES"));
        assert!(prompt.contains("CWE-79"));
        assert!(prompt.contains(source));
    }

    #[test]
    fn test_path_traversal_hunt_prompt() {
        let source = "fs.open(user_path)";
        let prompt = path_traversal_hunt_prompt(source);

        assert!(prompt.contains("PATH TRAVERSAL/SSRF"));
        assert!(prompt.contains("CWE-22"));
        assert!(prompt.contains(source));
    }

    #[test]
    fn test_crypto_hunt_prompt() {
        let source = "MD5(password)";
        let prompt = crypto_hunt_prompt(source);

        assert!(prompt.contains("CRYPTOGRAPHIC VULNERABILITIES"));
        assert!(prompt.contains(source));
    }

    #[test]
    fn test_resource_hunt_prompt() {
        let source = "malloc(size)";
        let prompt = resource_hunt_prompt(source);

        assert!(prompt.contains("RESOURCE HANDLING"));
        assert!(prompt.contains(source));
    }

    #[test]
    fn test_deserialization_hunt_prompt() {
        let source = "yaml.load(user_input)";
        let prompt = deserialization_hunt_prompt(source);

        assert!(prompt.contains("DESERIALIZATION/CONFIG"));
        assert!(prompt.contains(source));
    }

    // Test edge cases
    #[test]
    fn test_hunt_prompts_with_empty_source() {
        let prompt = injection_hunt_prompt("");
        assert!(prompt.contains("INJECTION VULNERABILITIES"));
    }

    #[test]
    fn test_all_baco_phase_variants() {
        let phases = vec![
            BacoPhase::Indexing,
            BacoPhase::Semgrep,
            BacoPhase::LlmStaticAnalysis,
            BacoPhase::LlmDiscovery,
            BacoPhase::LlmVerification,
            BacoPhase::TicketCrossRef,
            BacoPhase::GitAnalysis,
            BacoPhase::CrossFileAnalysis,
            BacoPhase::ConfidenceScoring,
            BacoPhase::AiAggregation,
            BacoPhase::Reporting,
            BacoPhase::Hunt,
            BacoPhase::Validate,
            BacoPhase::IndependentVerify,
        ];

        for phase in phases {
            let s = phase.to_string();
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_all_project_type_variants() {
        let types = vec![
            ProjectType::CLI,
            ProjectType::Web,
            ProjectType::Library,
            ProjectType::Embedded,
            ProjectType::Firmware,
            ProjectType::Desktop,
        ];

        for t in types {
            let s = t.to_string();
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_template_variables_operations() {
        let mut vars = TemplateVariables::new();

        vars.insert("KEY1".to_string(), "value1".to_string());
        assert_eq!(vars.len(), 1);

        assert_eq!(vars.get("KEY1"), Some(&"value1".to_string()));
        assert_eq!(vars.get("NONEXISTENT"), None);

        vars.insert("KEY2".to_string(), "value2".to_string());
        vars.insert("KEY3".to_string(), "value3".to_string());
        assert_eq!(vars.len(), 3);
    }

    #[test]
    fn test_get_default_prompt_t25_phases() {
        let project_type = ProjectType::Web;

        let hunt_prompt = get_default_prompt(&BacoPhase::Hunt, &project_type);
        assert!(!hunt_prompt.is_empty());

        let validate_prompt = get_default_prompt(&BacoPhase::Validate, &project_type);
        assert!(!validate_prompt.is_empty());

        let independent_verify_prompt =
            get_default_prompt(&BacoPhase::IndependentVerify, &project_type);
        assert!(!independent_verify_prompt.is_empty());
    }

    #[test]
    fn test_default_prompts_debug_output() {
        let prompts = get_all_defaults();
        let debug_str = format!("{:?}", prompts);

        assert!(debug_str.contains("indexing"));
        assert!(debug_str.contains("semgrep"));
        assert!(debug_str.contains("llm_static_analysis"));
    }

    #[test]
    fn test_prompt_spec_default() {
        let spec = PromptSpec::default();
        assert_eq!(spec.prompt_template, "llm_static_analysis");
        assert!(spec.model_override.is_none());
    }
}
