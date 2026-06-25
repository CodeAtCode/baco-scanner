//! Pattern detection logic for vulnerability and risky commit detection.

use regex::Regex;
pub use crate::git_analysis::models::{RiskyPatternType, VulnerabilityPatternType};

/// Compiled vulnerability patterns for detection
pub fn compile_vulnerability_patterns() -> Vec<(Regex, VulnerabilityPatternType, &'static str)> {
    vec![
        // CWE references
        (
            Regex::new(r"(?i)CWE-\d+").unwrap(),
            VulnerabilityPatternType::SecurityVulnerability,
            "CWE reference in commit",
        ),
        // CVE references
        (
            Regex::new(r"(?i)CVE-\d{4}-\d+").unwrap(),
            VulnerabilityPatternType::SecurityVulnerability,
            "CVE reference in commit",
        ),
        // Security fix patterns
        (
            Regex::new(r"(?i)(?:fix|patch|repair)\s+(?:for\s+)?(?:the\s+)?(?:security\s+)?(?:vulnerability|issue|bug|flaw)").unwrap(),
            VulnerabilityPatternType::SecurityFix,
            "Security fix commit",
        ),
        // XSS
        (
            Regex::new(r"(?i)xss|cross[_-]site[_-]scripting").unwrap(),
            VulnerabilityPatternType::InjectionRisk,
            "XSS vulnerability",
        ),
        // SQL Injection
        (
            Regex::new(r"(?i)(?:sql|sqli)[_-]?injection").unwrap(),
            VulnerabilityPatternType::InjectionRisk,
            "SQL injection vulnerability",
        ),
        // Command injection
        (
            Regex::new(r"(?i)(?:command|cmd|shell|code)\s+injection").unwrap(),
            VulnerabilityPatternType::InjectionRisk,
            "Command injection vulnerability",
        ),
        // Path traversal
        (
            Regex::new(r"(?i)(?:path|directory)\s+traversal").unwrap(),
            VulnerabilityPatternType::InjectionRisk,
            "Path traversal vulnerability",
        ),
        // Authentication bypass
        (
            Regex::new(r"(?i)(?:auth(?:entication|orization)?\s+(?:bypass|broken|fail))").unwrap(),
            VulnerabilityPatternType::AuthIssue,
            "Authentication bypass",
        ),
        // Encryption issues
        (
            Regex::new(r"(?i)(?:weak\s+encryption|insecure\s+crypto|broken\s+crypto|cryptographic\s+(?:flaw|bug|issue))").unwrap(),
            VulnerabilityPatternType::CryptoMisuse,
            "Cryptographic weakness",
        ),
        // Deprecated security
        (
            Regex::new(r"(?i)(?:deprecat|obsolete).*(?:security|crypt|auth)").unwrap(),
            VulnerabilityPatternType::SecurityDeprecation,
            "Security deprecation",
        ),
        // TODO/FIXME security
        (
            Regex::new(r"(?i)(?:TODO|FIXME|HACK|XXX).*(?:security|vulnerability|injection|XSS|SQL|CWE)").unwrap(),
            VulnerabilityPatternType::SecurityTodo,
            "Security TODO in code",
        ),
    ]
}

/// Compiled risky patterns for detection
pub fn compile_risky_patterns() -> Vec<(Regex, RiskyPatternType, f32)> {
    vec![
        // Emergency/hotfix patterns
        (
            Regex::new(r"(?i)(?:emergency|hotfix|urgent|critical\s+fix|asap)").unwrap(),
            RiskyPatternType::EmergencyCommit,
            0.3,
        ),
        // Security bypass
        (
            Regex::new(
                r"(?i)(?:bypass|skip|disable|ignore).*(?:security|auth|check|validation)",
            )
            .unwrap(),
            RiskyPatternType::SecurityBypass,
            0.5,
        ),
        // Revert
        (
            Regex::new(r"(?i)^(?:revert|reverted).*").unwrap(),
            RiskyPatternType::Revert,
            0.2,
        ),
        // Merge conflicts mentioned
        (
            Regex::new(r"(?i)(?:merge\s+conflict|resolved\s+conflict)").unwrap(),
            RiskyPatternType::MergeWithConflicts,
            0.15,
        ),
    ]
}

/// Security-related keywords for commit message analysis
pub fn get_security_keywords() -> Vec<&'static str> {
    vec![
        "security",
        "vulnerability",
        "vulnerable",
        "exploit",
        "injection",
        "xss",
        "csrf",
        "cors",
        "authentication",
        "authorization",
        "encryption",
        "cryptography",
        "hash",
        "password",
        "credential",
        "token",
        "secret",
        "key",
        "sanitize",
        "escape",
        "validate",
        "verify",
        "permission",
        "access control",
        "broken",
        "bypass",
        "cwe",
        "cve",
    ]
}

/// Analyze a commit message for security-related content
pub fn analyze_commit_message(message: &str, security_keywords: &[&str]) -> (bool, Vec<String>) {
    let mut is_security_fix = false;
    let mut cwe_references = Vec::new();

    let lower_message = message.to_lowercase();

    // Check for security keywords
    for keyword in security_keywords {
        if lower_message.contains(keyword) {
            is_security_fix = true;
            break;
        }
    }

    // Extract CWE references
    if let Ok(cwe_regex) = Regex::new(r"CWE-(\d+)") {
        for cap in cwe_regex.captures_iter(message) {
            if let Some(m) = cap.get(0) {
                cwe_references.push(m.as_str().to_string());
            }
        }
    }

    (is_security_fix, cwe_references)
}

/// Calculate confidence score for a detected pattern
pub fn calculate_pattern_confidence(
    commit_timestamp: i64,
    is_security_fix: bool,
    cwe_references_count: usize,
    pattern_type: &VulnerabilityPatternType,
) -> f32 {
    let mut confidence: f32 = 0.5;

    // Recent commits are more relevant
    let age_days = (chrono::Utc::now().timestamp() - commit_timestamp) / 86400;
    if age_days < 30 {
        confidence += 0.2;
    } else if age_days < 90 {
        confidence += 0.1;
    }

    // Direct security mentions increase confidence
    if is_security_fix {
        confidence += 0.2;
    }

    // CWE references add confidence
    if cwe_references_count > 0 {
        confidence += 0.15;
    }

    // Security fix pattern type adds confidence
    match pattern_type {
        VulnerabilityPatternType::SecurityVulnerability => confidence += 0.15,
        VulnerabilityPatternType::SecurityFix => confidence += 0.15,
        _ => {}
    }

    confidence.min(1.0)
}
