//! Pattern detection logic for vulnerability and risky commit detection.

pub use crate::git_analysis::models::{RiskyPatternType, VulnerabilityPatternType};
use regex::Regex;

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
            Regex::new(r"(?i)(?:bypass|skip|disable|ignore).*(?:security|auth|check|validation)")
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
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_vulnerability_patterns() {
        let patterns = compile_vulnerability_patterns();
        assert!(!patterns.is_empty());
        // Should have at least 11 patterns
        assert!(patterns.len() >= 11);
    }

    #[test]
    fn test_compile_risky_patterns() {
        let patterns = compile_risky_patterns();
        assert!(!patterns.is_empty());
        // Should have at least 4 patterns
        assert!(patterns.len() >= 4);
    }

    #[test]
    fn test_get_security_keywords() {
        let keywords = get_security_keywords();
        assert!(!keywords.is_empty());
        // Should have at least 25 keywords
        assert!(keywords.len() >= 25);

        // Check for expected keywords
        assert!(keywords.contains(&"security"));
        assert!(keywords.contains(&"vulnerability"));
        assert!(keywords.contains(&"xss"));
        assert!(keywords.contains(&"cwe"));
        assert!(keywords.contains(&"cve"));
    }

    #[test]
    fn test_vulnerability_pattern_cwe_matching() {
        let patterns = compile_vulnerability_patterns();
        let cwe_regex = &patterns[0].0;

        assert!(cwe_regex.is_match("Fix CWE-79 vulnerability"));
        assert!(cwe_regex.is_match("Address CWE-89 SQL injection"));
        assert!(!cwe_regex.is_match("Normal commit message"));
    }

    #[test]
    fn test_vulnerability_pattern_cve_matching() {
        let patterns = compile_vulnerability_patterns();
        let cve_regex = &patterns[1].0;

        assert!(cve_regex.is_match("Fix CVE-2024-1234"));
        assert!(cve_regex.is_match("Patch CVE-2023-9999 vulnerability"));
        assert!(!cve_regex.is_match("CVE-202-1234")); // Invalid format
        assert!(!cve_regex.is_match("Normal commit"));
    }

    #[test]
    fn test_vulnerability_pattern_security_fix_matching() {
        let patterns = compile_vulnerability_patterns();
        let security_fix_regex = &patterns[2].0;

        assert!(security_fix_regex.is_match("Fix security issue"));
        assert!(security_fix_regex.is_match("Patch the vulnerability"));
        assert!(security_fix_regex.is_match("Fix for security bug"));
        assert!(security_fix_regex.is_match("Repair security flaw"));
        assert!(!security_fix_regex.is_match("Normal feature addition"));
    }

    #[test]
    fn test_vulnerability_pattern_xss_matching() {
        let patterns = compile_vulnerability_patterns();
        let xss_regex = &patterns[3].0;

        assert!(xss_regex.is_match("Fix XSS vulnerability"));
        assert!(xss_regex.is_match("cross-site-scripting fix"));
        assert!(xss_regex.is_match("cross_site_scripting prevention"));
        assert!(!xss_regex.is_match("Normal commit"));
    }

    #[test]
    fn test_vulnerability_pattern_sql_injection_matching() {
        let patterns = compile_vulnerability_patterns();
        let sql_regex = &patterns[4].0;

        assert!(sql_regex.is_match("Fix SQL-injection"));
        assert!(sql_regex.is_match("SQL_injection patch"));
        assert!(sql_regex.is_match("sqli_injection fix"));
        assert!(!sql_regex.is_match("Normal database query"));
    }

    #[test]
    fn test_vulnerability_pattern_command_injection_matching() {
        let patterns = compile_vulnerability_patterns();
        let cmd_regex = &patterns[5].0;

        assert!(cmd_regex.is_match("Fix command injection"));
        assert!(cmd_regex.is_match("Shell injection vulnerability"));
        assert!(cmd_regex.is_match("Code injection fix"));
        assert!(!cmd_regex.is_match("Normal command execution"));
    }

    #[test]
    fn test_vulnerability_pattern_path_traversal_matching() {
        let patterns = compile_vulnerability_patterns();
        let path_regex = &patterns[6].0;

        assert!(path_regex.is_match("Fix path traversal"));
        assert!(path_regex.is_match("Directory traversal vulnerability"));
        assert!(!path_regex.is_match("Normal file path"));
    }

    #[test]
    fn test_vulnerability_pattern_auth_bypass_matching() {
        let patterns = compile_vulnerability_patterns();
        let auth_regex = &patterns[7].0;

        assert!(auth_regex.is_match("Fix authentication bypass"));
        assert!(auth_regex.is_match("Authorization broken"));
        assert!(auth_regex.is_match("Auth fail"));
        assert!(!auth_regex.is_match("Normal authentication"));
    }

    #[test]
    fn test_vulnerability_pattern_crypto_matching() {
        let patterns = compile_vulnerability_patterns();
        let crypto_regex = &patterns[8].0;

        assert!(crypto_regex.is_match("Fix weak encryption"));
        assert!(crypto_regex.is_match("Insecure crypto usage"));
        assert!(crypto_regex.is_match("Broken crypto fix"));
        assert!(crypto_regex.is_match("Cryptographic flaw"));
        assert!(!crypto_regex.is_match("Normal encryption"));
    }

    #[test]
    fn test_vulnerability_pattern_security_todo_matching() {
        let patterns = compile_vulnerability_patterns();
        let todo_regex = &patterns[10].0;

        assert!(todo_regex.is_match("TODO: fix security issue"));
        assert!(todo_regex.is_match("FIXME: XSS vulnerability"));
        assert!(todo_regex.is_match("XXX: SQL injection risk"));
        assert!(todo_regex.is_match("HACK: CWE-79 workaround"));
        assert!(!todo_regex.is_match("TODO: add feature"));
    }

    #[test]
    fn test_risky_pattern_emergency_matching() {
        let patterns = compile_risky_patterns();
        let emergency_regex = &patterns[0].0;

        assert!(emergency_regex.is_match("Emergency fix"));
        assert!(emergency_regex.is_match("Hotfix for bug"));
        assert!(emergency_regex.is_match("Urgent patch"));
        assert!(emergency_regex.is_match("Critical fix needed"));
        assert!(emergency_regex.is_match("ASAP deployment"));
        assert!(!emergency_regex.is_match("Normal commit"));
    }

    #[test]
    fn test_risky_pattern_security_bypass_matching() {
        let patterns = compile_risky_patterns();
        let bypass_regex = &patterns[1].0;

        assert!(bypass_regex.is_match("Bypass security check"));
        assert!(bypass_regex.is_match("Skip auth validation"));
        assert!(bypass_regex.is_match("Disable security"));
        assert!(bypass_regex.is_match("Ignore validation"));
        assert!(!bypass_regex.is_match("Normal security check"));
    }

    #[test]
    fn test_risky_pattern_revert_matching() {
        let patterns = compile_risky_patterns();
        let revert_regex = &patterns[2].0;

        assert!(revert_regex.is_match("Revert changes"));
        assert!(revert_regex.is_match("Reverted previous commit"));
        assert!(!revert_regex.is_match("Normal commit"));
    }

    #[test]
    fn test_risky_pattern_merge_conflicts_matching() {
        let patterns = compile_risky_patterns();
        let merge_regex = &patterns[3].0;

        assert!(merge_regex.is_match("Merge conflict resolved"));
        assert!(merge_regex.is_match("Fixed merge conflict"));
        assert!(!merge_regex.is_match("Normal merge"));
    }

    #[test]
    fn test_analyze_commit_message_security_keyword() {
        let keywords = get_security_keywords();
        let (is_security, cwe_refs) = analyze_commit_message("Fix security issue", &keywords);

        assert!(is_security);
        assert!(cwe_refs.is_empty());
    }

    #[test]
    fn test_analyze_commit_message_with_cwe() {
        let keywords = get_security_keywords();
        let (is_security, cwe_refs) = analyze_commit_message("Fix CWE-79 and CWE-89", &keywords);

        assert!(is_security);
        assert_eq!(cwe_refs.len(), 2);
        assert!(cwe_refs.contains(&"CWE-79".to_string()));
        assert!(cwe_refs.contains(&"CWE-89".to_string()));
    }

    #[test]
    fn test_analyze_commit_message_no_security() {
        let keywords = get_security_keywords();
        let (is_security, cwe_refs) = analyze_commit_message("Add new feature", &keywords);

        assert!(!is_security);
        assert!(cwe_refs.is_empty());
    }

    #[test]
    fn test_analyze_commit_message_empty() {
        let keywords = get_security_keywords();
        let (is_security, cwe_refs) = analyze_commit_message("", &keywords);

        assert!(!is_security);
        assert!(cwe_refs.is_empty());
    }

    #[test]
    fn test_analyze_commit_message_special_characters() {
        let keywords = get_security_keywords();
        let (is_security, cwe_refs) = analyze_commit_message("Fix security! @#$% issue", &keywords);

        assert!(is_security);
        assert!(cwe_refs.is_empty());
    }

    #[test]
    fn test_calculate_pattern_confidence_recent_commit() {
        let now = chrono::Utc::now().timestamp();
        let confidence =
            calculate_pattern_confidence(now, true, 1, &VulnerabilityPatternType::SecurityFix);

        // Recent + security fix + CWE should give high confidence
        assert!(confidence >= 0.85);
        assert!(confidence <= 1.0);
    }

    #[test]
    fn test_calculate_pattern_confidence_old_commit() {
        let old_timestamp = chrono::Utc::now().timestamp() - (100 * 86400); // 100 days ago
        let confidence = calculate_pattern_confidence(
            old_timestamp,
            false,
            0,
            &VulnerabilityPatternType::InjectionRisk,
        );

        // Old commit without security fix should have base confidence
        assert!(confidence >= 0.5);
        assert!(confidence < 0.8);
    }

    #[test]
    fn test_calculate_pattern_confidence_security_fix_boost() {
        let now = chrono::Utc::now().timestamp();
        let confidence = calculate_pattern_confidence(
            now,
            true,
            0,
            &VulnerabilityPatternType::SecurityVulnerability,
        );

        // Security fix should boost confidence
        assert!(confidence >= 0.7);
    }

    #[test]
    fn test_calculate_pattern_confidence_clamped() {
        let now = chrono::Utc::now().timestamp();
        // Many boosters should be clamped
        let confidence =
            calculate_pattern_confidence(now, true, 5, &VulnerabilityPatternType::SecurityFix);

        assert!(confidence <= 1.0);
    }

    #[test]
    fn test_pattern_case_insensitivity() {
        let patterns = compile_vulnerability_patterns();
        let xss_regex = &patterns[3].0;

        assert!(xss_regex.is_match("XSS"));
        assert!(xss_regex.is_match("xss"));
        assert!(xss_regex.is_match("Xss"));
        assert!(xss_regex.is_match("CROSS-SITE-SCRIPTING"));
        assert!(xss_regex.is_match("cross_site_scripting"));
    }
}
