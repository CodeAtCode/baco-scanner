//! Embedded default prompt templates for all BACO phases and project types.
//! These templates can be overridden via config.toml [phases.phase_name] sections.

use std::collections::HashMap;

/// All 11 BACO phases
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
    }
}

/// Get all default prompts
pub fn get_all_defaults() -> DefaultPrompts {
    DefaultPrompts::default()
}
