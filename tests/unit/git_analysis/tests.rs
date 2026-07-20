//! Comprehensive unit tests for the git_analysis module.
//!
//! This test suite covers:
//! - Git history analysis
//! - Pattern matching (vulnerability and risky patterns)
//! - Commit analysis
//! - Confidence calculation
//! - Helper functions
//! - Model operations

#[cfg(test)]
mod git_analysis_tests {
    use baco::analysis_context::AnalysisContext;
    use baco::git_analysis::helpers::{
        calculate_overall_confidence, get_commit_stats, update_context,
    };
    use baco::git_analysis::patterns::{
        analyze_commit_message, calculate_pattern_confidence, compile_risky_patterns,
        compile_vulnerability_patterns, get_security_keywords,
    };
    use baco::git_analysis::{
        CommitReference, GitAnalysisResult, GitConfidenceModifier, RiskyCommitPattern,
        RiskyPatternType, VulnerabilityPattern, VulnerabilityPatternType,
    };

    // ========================================================================
    // Pattern Compilation Tests
    // ========================================================================

    #[test]
    fn test_compile_vulnerability_patterns_returns_non_empty() {
        let patterns = compile_vulnerability_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.len() >= 10);
    }

    #[test]
    fn test_compile_risky_patterns_returns_non_empty() {
        let patterns = compile_risky_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.len() >= 4);
    }

    #[test]
    fn test_vulnerability_pattern_cwe_detection() {
        let patterns = compile_vulnerability_patterns();
        let cwe_pattern = patterns
            .iter()
            .find(|(_, _, desc)| desc.contains("CWE reference"))
            .unwrap();

        assert!(cwe_pattern.0.is_match("Fix CWE-79 in authentication"));
        assert!(cwe_pattern.0.is_match("Address CWE-89 SQL injection"));
        assert!(!cwe_pattern.0.is_match("Regular commit message"));
    }

    #[test]
    fn test_vulnerability_pattern_cve_detection() {
        let patterns = compile_vulnerability_patterns();
        let cve_pattern = patterns
            .iter()
            .find(|(_, _, desc)| desc.contains("CVE reference"))
            .unwrap();

        assert!(cve_pattern.0.is_match("Fix CVE-2024-1234"));
        assert!(cve_pattern.0.is_match("Patch CVE-2023-9876 vulnerability"));
        assert!(!cve_pattern.0.is_match("Regular commit"));
    }

    #[test]
    fn test_vulnerability_pattern_xss_detection() {
        let patterns = compile_vulnerability_patterns();
        let xss_pattern = patterns
            .iter()
            .find(|(_, _, desc)| desc.contains("XSS"))
            .unwrap();

        // Pattern: (?i)xss|cross[_-]site[_-]scripting
        assert!(xss_pattern.0.is_match("Fix XSS vulnerability"));
        assert!(xss_pattern.0.is_match("xss fix"));
        assert!(xss_pattern.0.is_match("cross_site_scripting"));
    }

    #[test]
    fn test_vulnerability_pattern_sql_injection_detection() {
        let patterns = compile_vulnerability_patterns();
        let sqli_pattern = patterns
            .iter()
            .find(|(_, _, desc)| desc.contains("SQL injection"))
            .unwrap();

        // Pattern: (?i)(?:sql|sqli)[_-]?injection - requires sql/sqli directly followed by
        // optional underscore/hyphen and then "injection"
        assert!(sqli_pattern.0.is_match("SQLinjection fix"));
        assert!(sqli_pattern.0.is_match("sql-injection fix"));
        assert!(sqli_pattern.0.is_match("sql_injection"));
    }

    #[test]
    fn test_vulnerability_pattern_command_injection_detection() {
        let patterns = compile_vulnerability_patterns();
        let cmd_inj_pattern = patterns
            .iter()
            .find(|(_, _, desc)| desc.contains("Command injection"))
            .unwrap();

        assert!(cmd_inj_pattern.0.is_match("Fix command injection"));
        assert!(cmd_inj_pattern.0.is_match("Shell injection vulnerability"));
        assert!(cmd_inj_pattern.0.is_match("Code injection patch"));
    }

    #[test]
    fn test_vulnerability_pattern_auth_bypass_detection() {
        let patterns = compile_vulnerability_patterns();
        let auth_pattern = patterns
            .iter()
            .find(|(_, _, desc)| desc.contains("Authentication"))
            .unwrap();

        assert!(auth_pattern.0.is_match("Fix authentication bypass"));
        assert!(auth_pattern.0.is_match("Authorization broken"));
        assert!(auth_pattern.0.is_match("Auth fail in login"));
    }

    #[test]
    fn test_vulnerability_pattern_crypto_misuse_detection() {
        let patterns = compile_vulnerability_patterns();
        let crypto_pattern = patterns
            .iter()
            .find(|(_, _, desc)| desc.contains("Cryptographic"))
            .unwrap();

        assert!(crypto_pattern.0.is_match("Fix weak encryption"));
        assert!(crypto_pattern.0.is_match("Insecure crypto usage"));
        assert!(crypto_pattern.0.is_match("Broken crypto algorithm"));
    }

    #[test]
    fn test_vulnerability_pattern_security_todo_detection() {
        let patterns = compile_vulnerability_patterns();
        let todo_pattern = patterns
            .iter()
            .find(|(_, _, desc)| desc.contains("Security TODO"))
            .unwrap();

        assert!(todo_pattern.0.is_match("TODO: fix security issue"));
        assert!(todo_pattern.0.is_match("FIXME: XSS vulnerability"));
        assert!(todo_pattern.0.is_match("XXX: CWE-79 needs fixing"));
    }

    #[test]
    fn test_risky_pattern_emergency_detection() {
        let patterns = compile_risky_patterns();
        let emergency_pattern = patterns
            .iter()
            .find(|(_, pt, _)| *pt == RiskyPatternType::EmergencyCommit)
            .unwrap();

        assert!(emergency_pattern.0.is_match("Emergency fix for production"));
        assert!(emergency_pattern.0.is_match("Hotfix: critical bug"));
        assert!(emergency_pattern.0.is_match("Urgent security patch"));
        assert!(emergency_pattern.0.is_match("ASAP deployment"));
    }

    #[test]
    fn test_risky_pattern_security_bypass_detection() {
        let patterns = compile_risky_patterns();
        let bypass_pattern = patterns
            .iter()
            .find(|(_, pt, _)| *pt == RiskyPatternType::SecurityBypass)
            .unwrap();

        assert!(bypass_pattern.0.is_match("Bypass security check"));
        assert!(bypass_pattern.0.is_match("Skip auth validation"));
        assert!(bypass_pattern.0.is_match("Disable security checks"));
    }

    #[test]
    fn test_risky_pattern_revert_detection() {
        let patterns = compile_risky_patterns();
        let revert_pattern = patterns
            .iter()
            .find(|(_, pt, _)| *pt == RiskyPatternType::Revert)
            .unwrap();

        assert!(revert_pattern.0.is_match("Revert security fix"));
        assert!(revert_pattern.0.is_match("Reverted changes"));
        assert!(revert_pattern.0.is_match("revert: bad commit"));
    }

    // ========================================================================
    // Security Keywords Tests
    // ========================================================================

    #[test]
    fn test_get_security_keywords_returns_non_empty() {
        let keywords = get_security_keywords();
        assert!(!keywords.is_empty());
        assert!(keywords.len() >= 25);
    }

    #[test]
    fn test_security_keywords_contains_expected_terms() {
        let keywords = get_security_keywords();

        assert!(keywords.contains(&"security"));
        assert!(keywords.contains(&"vulnerability"));
        assert!(keywords.contains(&"authentication"));
        assert!(keywords.contains(&"encryption"));
        assert!(keywords.contains(&"cwe"));
        assert!(keywords.contains(&"cve"));
    }

    // ========================================================================
    // Commit Message Analysis Tests
    // ========================================================================

    #[test]
    fn test_analyze_commit_message_security_fix() {
        let keywords = get_security_keywords();
        let (is_security_fix, cwe_refs) =
            analyze_commit_message("Fix security vulnerability in auth", &keywords);

        assert!(is_security_fix);
        assert!(cwe_refs.is_empty());
    }

    #[test]
    fn test_analyze_commit_message_with_cwe() {
        let keywords = get_security_keywords();
        let (is_security_fix, cwe_refs) =
            analyze_commit_message("Fix CWE-79 XSS vulnerability", &keywords);

        assert!(is_security_fix);
        assert_eq!(cwe_refs.len(), 1);
        assert_eq!(cwe_refs[0], "CWE-79");
    }

    #[test]
    fn test_analyze_commit_message_multiple_cwes() {
        let keywords = get_security_keywords();
        let (is_security_fix, cwe_refs) =
            analyze_commit_message("Fix CWE-79 and CWE-89 vulnerabilities", &keywords);

        assert!(is_security_fix);
        assert_eq!(cwe_refs.len(), 2);
        assert!(cwe_refs.iter().any(|r| r == "CWE-79"));
        assert!(cwe_refs.iter().any(|r| r == "CWE-89"));
    }

    #[test]
    fn test_analyze_commit_message_no_security() {
        let keywords = get_security_keywords();
        let (is_security_fix, cwe_refs) = analyze_commit_message("Regular bug fix", &keywords);

        assert!(!is_security_fix);
        assert!(cwe_refs.is_empty());
    }

    #[test]
    fn test_analyze_commit_message_cve_reference() {
        let keywords = get_security_keywords();
        let (is_security_fix, cwe_refs) =
            analyze_commit_message("Patch CVE-2024-1234 vulnerability", &keywords);

        assert!(is_security_fix);
        assert!(cwe_refs.is_empty()); // CVE is not CWE
    }

    #[test]
    fn test_analyze_commit_message_case_insensitive() {
        let keywords = get_security_keywords();
        let (is_security_fix, _) = analyze_commit_message("FIX SECURITY ISSUE", &keywords);

        assert!(is_security_fix);
    }

    // ========================================================================
    // Pattern Confidence Calculation Tests
    // ========================================================================

    #[test]
    fn test_calculate_pattern_confidence_recent_commit() {
        // Recent commit (within 30 days)
        let recent_timestamp = chrono::Utc::now().timestamp() - (15 * 86400);
        let confidence = calculate_pattern_confidence(
            recent_timestamp,
            false,
            0,
            &VulnerabilityPatternType::SecurityVulnerability,
        );

        assert!(confidence >= 0.7); // Base 0.5 + 0.2 (recent) + 0.15 (pattern type)
    }

    #[test]
    fn test_calculate_pattern_confidence_security_fix_bonus() {
        let timestamp = chrono::Utc::now().timestamp() - (15 * 86400);
        let confidence = calculate_pattern_confidence(
            timestamp,
            true, // is_security_fix
            0,
            &VulnerabilityPatternType::SecurityFix,
        );

        assert!(confidence >= 0.85); // Base 0.5 + 0.2 (recent) + 0.2 (security fix) + 0.15 (pattern type)
    }

    #[test]
    fn test_calculate_pattern_confidence_cwe_bonus() {
        let timestamp = chrono::Utc::now().timestamp() - (15 * 86400);
        let confidence = calculate_pattern_confidence(
            timestamp,
            false,
            2, // 2 CWE references
            &VulnerabilityPatternType::SecurityVulnerability,
        );

        assert!(confidence >= 0.85); // Base 0.5 + 0.2 (recent) + 0.15 (CWE) + 0.15 (pattern type)
    }

    #[test]
    fn test_calculate_pattern_confidence_old_commit() {
        // Old commit (over 90 days)
        let old_timestamp = chrono::Utc::now().timestamp() - (100 * 86400);
        let confidence = calculate_pattern_confidence(
            old_timestamp,
            false,
            0,
            &VulnerabilityPatternType::SecurityTodo,
        );

        assert!(confidence >= 0.5); // Just base score
        assert!(confidence <= 0.6);
    }

    #[test]
    fn test_calculate_pattern_confidence_max_cap() {
        // Maximum bonuses should be capped at 1.0
        let recent_timestamp = chrono::Utc::now().timestamp() - (15 * 86400);
        let confidence = calculate_pattern_confidence(
            recent_timestamp,
            true,
            5, // Multiple CWE references
            &VulnerabilityPatternType::SecurityFix,
        );

        assert!(confidence <= 1.0);
    }

    // ========================================================================
    // Overall Confidence Calculation Tests
    // ========================================================================

    #[test]
    fn test_calculate_overall_confidence_no_commits() {
        let commits: Vec<CommitReference> = vec![];
        let patterns: Vec<VulnerabilityPattern> = vec![];
        let risky: Vec<RiskyCommitPattern> = vec![];

        let confidence = calculate_overall_confidence(&commits, &patterns, &risky);

        assert_eq!(confidence, 0.3); // No history penalty
    }

    #[test]
    fn test_calculate_overall_confidence_security_commits_bonus() {
        let commits = vec![
            CommitReference {
                commit_hash: "abc12345".to_string(),
                commit_message: "Fix security issue".to_string(),
                author: "Test".to_string(),
                author_email: "test@test.com".to_string(),
                timestamp: chrono::Utc::now().timestamp(),
                modified_files: vec!["test.rs".to_string()],
                lines_added: 10,
                lines_deleted: 5,
                is_security_fix: true,
                cwe_references: vec![],
            },
            CommitReference {
                commit_hash: "def67890".to_string(),
                commit_message: "Another security fix".to_string(),
                author: "Test".to_string(),
                author_email: "test@test.com".to_string(),
                timestamp: chrono::Utc::now().timestamp(),
                modified_files: vec!["test.rs".to_string()],
                lines_added: 5,
                lines_deleted: 2,
                is_security_fix: true,
                cwe_references: vec![],
            },
        ];

        let patterns: Vec<VulnerabilityPattern> = vec![];
        let risky: Vec<RiskyCommitPattern> = vec![];

        let confidence = calculate_overall_confidence(&commits, &patterns, &risky);

        assert!(confidence > 0.5); // Base + security commit bonus
    }

    #[test]
    fn test_calculate_overall_confidence_cwe_refs_bonus() {
        let commits = vec![CommitReference {
            commit_hash: "abc12345".to_string(),
            commit_message: "Fix CWE-79".to_string(),
            author: "Test".to_string(),
            author_email: "test@test.com".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            modified_files: vec!["test.rs".to_string()],
            lines_added: 10,
            lines_deleted: 5,
            is_security_fix: false,
            cwe_references: vec!["CWE-79".to_string()],
        }];

        let patterns: Vec<VulnerabilityPattern> = vec![];
        let risky: Vec<RiskyCommitPattern> = vec![];

        let confidence = calculate_overall_confidence(&commits, &patterns, &risky);

        assert!(confidence > 0.5); // Base + CWE reference bonus
    }

    #[test]
    fn test_calculate_overall_confidence_risky_pattern_penalty() {
        let commits = vec![CommitReference {
            commit_hash: "abc12345".to_string(),
            commit_message: "Regular commit".to_string(),
            author: "Test".to_string(),
            author_email: "test@test.com".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            modified_files: vec!["test.rs".to_string()],
            lines_added: 10,
            lines_deleted: 5,
            is_security_fix: false,
            cwe_references: vec![],
        }];

        let patterns: Vec<VulnerabilityPattern> = vec![];
        let risky = vec![RiskyCommitPattern {
            pattern_type: RiskyPatternType::LargeChange,
            description: "Large change".to_string(),
            commit: "abc12345".to_string(),
            risk_score: 0.8,
        }];

        let confidence = calculate_overall_confidence(&commits, &patterns, &risky);

        assert!(confidence < 0.5); // Base - risky penalty
    }

    #[test]
    fn test_calculate_overall_confidence_mixed_factors() {
        let commits = vec![
            CommitReference {
                commit_hash: "abc12345".to_string(),
                commit_message: "Security fix".to_string(),
                author: "Test".to_string(),
                author_email: "test@test.com".to_string(),
                timestamp: chrono::Utc::now().timestamp(),
                modified_files: vec!["test.rs".to_string()],
                lines_added: 10,
                lines_deleted: 5,
                is_security_fix: true,
                cwe_references: vec!["CWE-79".to_string()],
            },
            CommitReference {
                commit_hash: "def67890".to_string(),
                commit_message: "Regular fix".to_string(),
                author: "Test".to_string(),
                author_email: "test@test.com".to_string(),
                timestamp: chrono::Utc::now().timestamp(),
                modified_files: vec!["test.rs".to_string()],
                lines_added: 5,
                lines_deleted: 2,
                is_security_fix: false,
                cwe_references: vec![],
            },
        ];

        let patterns = vec![VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::SecurityFix,
            description: "Security fix pattern".to_string(),
            cwe_id: Some("CWE-79".to_string()),
            commit: "abc12345".to_string(),
            confidence: 0.8,
        }];

        let risky = vec![RiskyCommitPattern {
            pattern_type: RiskyPatternType::Revert,
            description: "Revert".to_string(),
            commit: "def67890".to_string(),
            risk_score: 0.2,
        }];

        let confidence = calculate_overall_confidence(&commits, &patterns, &risky);

        assert!((0.5..=1.0).contains(&confidence));
    }

    #[test]
    fn test_calculate_overall_confidence_clamped_to_range() {
        // Many security commits and patterns should not exceed 1.0
        let commits: Vec<CommitReference> = (0..20)
            .map(|i| CommitReference {
                commit_hash: format!("abc{}", i),
                commit_message: "Security fix".to_string(),
                author: "Test".to_string(),
                author_email: "test@test.com".to_string(),
                timestamp: chrono::Utc::now().timestamp(),
                modified_files: vec!["test.rs".to_string()],
                lines_added: 10,
                lines_deleted: 5,
                is_security_fix: true,
                cwe_references: vec!["CWE-79".to_string()],
            })
            .collect();

        let patterns: Vec<VulnerabilityPattern> = (0..20)
            .map(|i| VulnerabilityPattern {
                pattern_type: VulnerabilityPatternType::SecurityFix,
                description: "Pattern".to_string(),
                cwe_id: Some("CWE-79".to_string()),
                commit: format!("abc{}", i),
                confidence: 0.8,
            })
            .collect();

        let risky: Vec<RiskyCommitPattern> = vec![];

        let confidence = calculate_overall_confidence(&commits, &patterns, &risky);

        assert!(confidence <= 1.0);
        assert!(confidence >= 0.0);
    }

    // ========================================================================
    // Commit Stats Tests
    // ========================================================================

    #[test]
    fn test_get_commit_stats_empty() {
        let commits: Vec<CommitReference> = vec![];
        let stats = get_commit_stats(&commits);

        assert_eq!(stats.get("total_commits"), Some(&0));
        assert_eq!(stats.get("security_commits"), Some(&0));
        assert_eq!(stats.get("total_additions"), Some(&0));
        assert_eq!(stats.get("total_deletions"), Some(&0));
    }

    #[test]
    fn test_get_commit_stats_with_data() {
        let commits = vec![
            CommitReference {
                commit_hash: "abc12345".to_string(),
                commit_message: "Security fix".to_string(),
                author: "Test".to_string(),
                author_email: "test@test.com".to_string(),
                timestamp: chrono::Utc::now().timestamp(),
                modified_files: vec!["test.rs".to_string()],
                lines_added: 10,
                lines_deleted: 5,
                is_security_fix: true,
                cwe_references: vec!["CWE-79".to_string()],
            },
            CommitReference {
                commit_hash: "def67890".to_string(),
                commit_message: "Regular fix".to_string(),
                author: "Test".to_string(),
                author_email: "test@test.com".to_string(),
                timestamp: chrono::Utc::now().timestamp(),
                modified_files: vec!["test.rs".to_string()],
                lines_added: 20,
                lines_deleted: 10,
                is_security_fix: false,
                cwe_references: vec![],
            },
        ];

        let stats = get_commit_stats(&commits);

        assert_eq!(stats.get("total_commits"), Some(&2));
        assert_eq!(stats.get("security_commits"), Some(&1));
        assert_eq!(stats.get("total_additions"), Some(&30));
        assert_eq!(stats.get("total_deletions"), Some(&15));
    }

    // ========================================================================
    // Context Update Tests
    // ========================================================================

    #[test]
    fn test_update_context_with_vulnerability_patterns() {
        let mut ctx = AnalysisContext::default();

        let result = GitAnalysisResult {
            related_commits: vec![],
            vulnerability_patterns: vec![VulnerabilityPattern {
                pattern_type: VulnerabilityPatternType::SecurityFix,
                description: "Test pattern".to_string(),
                cwe_id: Some("CWE-79".to_string()),
                commit: "abc12345".to_string(),
                confidence: 0.8,
            }],
            risky_patterns: vec![],
            confidence_modifiers: vec![],
            git_confidence_score: 0.7,
        };

        update_context(&mut ctx, &result);

        assert!(!ctx.findings_so_far.is_empty());
        assert!(ctx.findings_so_far[0].contains("[git]"));
    }

    #[test]
    fn test_update_context_with_security_commits() {
        let mut ctx = AnalysisContext::default();

        let result = GitAnalysisResult {
            related_commits: vec![CommitReference {
                commit_hash: "abc12345".to_string(),
                commit_message: "Security fix".to_string(),
                author: "Test".to_string(),
                author_email: "test@test.com".to_string(),
                timestamp: chrono::Utc::now().timestamp(),
                modified_files: vec!["test.rs".to_string()],
                lines_added: 10,
                lines_deleted: 5,
                is_security_fix: true,
                cwe_references: vec![],
            }],
            vulnerability_patterns: vec![],
            risky_patterns: vec![],
            confidence_modifiers: vec![GitConfidenceModifier {
                source: "security_commits".to_string(),
                modifier: 0.05,
                reason: "Found security commits".to_string(),
            }],
            git_confidence_score: 0.7,
        };

        update_context(&mut ctx, &result);

        assert!(!ctx.invariants.is_empty());
        assert!(ctx.invariants[0].contains("security fixes"));
    }

    #[test]
    fn test_update_context_empty_result() {
        let mut ctx = AnalysisContext::default();

        let result = GitAnalysisResult {
            related_commits: vec![],
            vulnerability_patterns: vec![],
            risky_patterns: vec![],
            confidence_modifiers: vec![],
            git_confidence_score: 0.3,
        };

        update_context(&mut ctx, &result);

        // Should not add findings or invariants for empty result
        assert!(ctx.findings_so_far.is_empty());
        assert!(ctx.invariants.is_empty());
    }

    // ========================================================================
    // Model Tests
    // ========================================================================

    #[test]
    fn test_vulnerability_pattern_type_to_string_security_vulnerability() {
        let pattern = VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::SecurityVulnerability,
            description: "Test".to_string(),
            cwe_id: None,
            commit: "abc12345".to_string(),
            confidence: 0.5,
        };

        assert_eq!(pattern.pattern_type_to_string(), "Security Vulnerability");
    }

    #[test]
    fn test_vulnerability_pattern_type_to_string_security_fix() {
        let pattern = VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::SecurityFix,
            description: "Test".to_string(),
            cwe_id: None,
            commit: "abc12345".to_string(),
            confidence: 0.5,
        };

        assert_eq!(pattern.pattern_type_to_string(), "Security Fix");
    }

    #[test]
    fn test_vulnerability_pattern_type_to_string_custom() {
        let pattern = VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::Custom("MyCustomPattern".to_string()),
            description: "Test".to_string(),
            cwe_id: None,
            commit: "abc12345".to_string(),
            confidence: 0.5,
        };

        assert_eq!(pattern.pattern_type_to_string(), "MyCustomPattern");
    }

    #[test]
    fn test_vulnerability_pattern_type_to_string_security_todo() {
        let pattern = VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::SecurityTodo,
            description: "Test".to_string(),
            cwe_id: None,
            commit: "abc12345".to_string(),
            confidence: 0.5,
        };

        assert_eq!(pattern.pattern_type_to_string(), "Security TODO");
    }

    #[test]
    fn test_vulnerability_pattern_type_to_string_security_deprecation() {
        let pattern = VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::SecurityDeprecation,
            description: "Test".to_string(),
            cwe_id: None,
            commit: "abc12345".to_string(),
            confidence: 0.5,
        };

        assert_eq!(pattern.pattern_type_to_string(), "Security Deprecation");
    }

    #[test]
    fn test_vulnerability_pattern_type_to_string_vulnerable_dependency() {
        let pattern = VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::VulnerableDependency,
            description: "Test".to_string(),
            cwe_id: None,
            commit: "abc12345".to_string(),
            confidence: 0.5,
        };

        assert_eq!(pattern.pattern_type_to_string(), "Vulnerable Dependency");
    }

    #[test]
    fn test_vulnerability_pattern_type_to_string_injection_risk() {
        let pattern = VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::InjectionRisk,
            description: "Test".to_string(),
            cwe_id: None,
            commit: "abc12345".to_string(),
            confidence: 0.5,
        };

        assert_eq!(pattern.pattern_type_to_string(), "Injection Risk");
    }

    #[test]
    fn test_vulnerability_pattern_type_to_string_auth_issue() {
        let pattern = VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::AuthIssue,
            description: "Test".to_string(),
            cwe_id: None,
            commit: "abc12345".to_string(),
            confidence: 0.5,
        };

        assert_eq!(pattern.pattern_type_to_string(), "Auth Issue");
    }

    #[test]
    fn test_commit_reference_creation() {
        let commit = CommitReference {
            commit_hash: "abc12345".to_string(),
            commit_message: "Test commit".to_string(),
            author: "Test User".to_string(),
            author_email: "test@example.com".to_string(),
            timestamp: 1234567890,
            modified_files: vec!["file1.rs".to_string(), "file2.rs".to_string()],
            lines_added: 100,
            lines_deleted: 50,
            is_security_fix: true,
            cwe_references: vec!["CWE-79".to_string(), "CWE-89".to_string()],
        };

        assert_eq!(commit.commit_hash, "abc12345");
        assert_eq!(commit.lines_added, 100);
        assert!(commit.is_security_fix);
        assert_eq!(commit.cwe_references.len(), 2);
    }

    #[test]
    fn test_risky_commit_pattern_creation() {
        let pattern = RiskyCommitPattern {
            pattern_type: RiskyPatternType::LargeChange,
            description: "Large change detected".to_string(),
            commit: "abc12345".to_string(),
            risk_score: 0.7,
        };

        assert_eq!(pattern.risk_score, 0.7);
        assert!(pattern.risk_score >= 0.0 && pattern.risk_score <= 1.0);
    }

    #[test]
    fn test_risky_pattern_type_large_change() {
        let pattern = RiskyCommitPattern {
            pattern_type: RiskyPatternType::LargeChange,
            description: "Test".to_string(),
            commit: "abc12345".to_string(),
            risk_score: 0.7,
        };

        assert!(matches!(
            pattern.pattern_type,
            RiskyPatternType::LargeChange
        ));
    }

    #[test]
    fn test_risky_pattern_type_emergency_commit() {
        let pattern = RiskyCommitPattern {
            pattern_type: RiskyPatternType::EmergencyCommit,
            description: "Test".to_string(),
            commit: "abc12345".to_string(),
            risk_score: 0.5,
        };

        assert!(matches!(
            pattern.pattern_type,
            RiskyPatternType::EmergencyCommit
        ));
    }

    #[test]
    fn test_risky_pattern_type_security_bypass() {
        let pattern = RiskyCommitPattern {
            pattern_type: RiskyPatternType::SecurityBypass,
            description: "Test".to_string(),
            commit: "abc12345".to_string(),
            risk_score: 0.9,
        };

        assert!(matches!(
            pattern.pattern_type,
            RiskyPatternType::SecurityBypass
        ));
    }

    #[test]
    fn test_risky_pattern_type_revert() {
        let pattern = RiskyCommitPattern {
            pattern_type: RiskyPatternType::Revert,
            description: "Test".to_string(),
            commit: "abc12345".to_string(),
            risk_score: 0.3,
        };

        assert!(matches!(pattern.pattern_type, RiskyPatternType::Revert));
    }

    #[test]
    fn test_risky_pattern_type_merge_conflicts() {
        let pattern = RiskyCommitPattern {
            pattern_type: RiskyPatternType::MergeWithConflicts,
            description: "Test".to_string(),
            commit: "abc12345".to_string(),
            risk_score: 0.4,
        };

        assert!(matches!(
            pattern.pattern_type,
            RiskyPatternType::MergeWithConflicts
        ));
    }

    #[test]
    fn test_risky_pattern_type_hotfix() {
        let pattern = RiskyCommitPattern {
            pattern_type: RiskyPatternType::Hotfix,
            description: "Test".to_string(),
            commit: "abc12345".to_string(),
            risk_score: 0.6,
        };

        assert!(matches!(pattern.pattern_type, RiskyPatternType::Hotfix));
    }

    #[test]
    fn test_risky_pattern_type_new_author() {
        let pattern = RiskyCommitPattern {
            pattern_type: RiskyPatternType::NewAuthor,
            description: "Test".to_string(),
            commit: "abc12345".to_string(),
            risk_score: 0.2,
        };

        assert!(matches!(pattern.pattern_type, RiskyPatternType::NewAuthor));
    }

    #[test]
    fn test_git_confidence_modifier_creation() {
        let modifier = GitConfidenceModifier {
            source: "test_source".to_string(),
            modifier: 0.1,
            reason: "Test reason".to_string(),
        };

        assert_eq!(modifier.modifier, 0.1);
        assert_eq!(modifier.source, "test_source");
    }

    #[test]
    fn test_git_analysis_result_creation() {
        let result = GitAnalysisResult {
            related_commits: vec![],
            vulnerability_patterns: vec![],
            risky_patterns: vec![],
            confidence_modifiers: vec![],
            git_confidence_score: 0.5,
        };

        assert_eq!(result.git_confidence_score, 0.5);
        assert!(result.related_commits.is_empty());
    }

    // ========================================================================
    // Regex Pattern Edge Cases
    // ========================================================================

    #[test]
    fn test_path_traversal_pattern() {
        let patterns = compile_vulnerability_patterns();
        let traversal_pattern = patterns
            .iter()
            .find(|(_, _, desc)| desc.contains("Path traversal"))
            .unwrap();

        assert!(traversal_pattern
            .0
            .is_match("Fix path traversal vulnerability"));
        assert!(traversal_pattern.0.is_match("Directory traversal fix"));
    }

    #[test]
    fn test_security_deprecation_pattern() {
        let patterns = compile_vulnerability_patterns();
        let deprecation_pattern = patterns
            .iter()
            .find(|(_, _, desc)| desc.contains("Security deprecation"))
            .unwrap();

        assert!(deprecation_pattern
            .0
            .is_match("Deprecate old security method"));
        assert!(deprecation_pattern.0.is_match("Obsolete crypto algorithm"));
    }

    #[test]
    fn test_merge_conflict_risky_pattern() {
        let patterns = compile_risky_patterns();
        let conflict_pattern = patterns
            .iter()
            .find(|(_, pt, _)| *pt == RiskyPatternType::MergeWithConflicts)
            .unwrap();

        assert!(conflict_pattern.0.is_match("Resolved merge conflict"));
        assert!(conflict_pattern.0.is_match("Merge conflict fix"));
    }

    // ========================================================================
    // Confidence Boundary Tests
    // ========================================================================

    #[test]
    fn test_confidence_never_exceeds_one() {
        // Even with all positive factors, confidence should not exceed 1.0
        let recent_timestamp = chrono::Utc::now().timestamp();

        let confidence = calculate_pattern_confidence(
            recent_timestamp,
            true,
            10,
            &VulnerabilityPatternType::SecurityFix,
        );

        assert!(confidence <= 1.0, "Confidence {} exceeds 1.0", confidence);
    }

    #[test]
    fn test_confidence_never_below_zero() {
        // With risky patterns, confidence should not go below 0.0
        let commits = vec![CommitReference {
            commit_hash: "abc12345".to_string(),
            commit_message: "Regular commit".to_string(),
            author: "Test".to_string(),
            author_email: "test@test.com".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            modified_files: vec!["test.rs".to_string()],
            lines_added: 10,
            lines_deleted: 5,
            is_security_fix: false,
            cwe_references: vec![],
        }];

        let patterns: Vec<VulnerabilityPattern> = vec![];
        let risky = vec![
            RiskyCommitPattern {
                pattern_type: RiskyPatternType::LargeChange,
                description: "Large".to_string(),
                commit: "abc12345".to_string(),
                risk_score: 0.8,
            },
            RiskyCommitPattern {
                pattern_type: RiskyPatternType::SecurityBypass,
                description: "Bypass".to_string(),
                commit: "abc12345".to_string(),
                risk_score: 0.5,
            },
        ];

        let confidence = calculate_overall_confidence(&commits, &patterns, &risky);

        assert!(confidence >= 0.0, "Confidence {} is below 0.0", confidence);
    }

    // ========================================================================
    // Keyword Matching Edge Cases
    // ========================================================================

    #[test]
    fn test_keyword_partial_match() {
        let keywords = get_security_keywords();
        let (is_security_fix, _) = analyze_commit_message("Fix for authentication bug", &keywords);

        assert!(is_security_fix); // "authentication" is a keyword
    }

    #[test]
    fn test_keyword_no_false_positive() {
        let keywords = get_security_keywords();
        let (is_security_fix, _) =
            analyze_commit_message("Add new feature for user dashboard", &keywords);

        assert!(!is_security_fix);
    }

    // ========================================================================
    // Pattern Matching Performance/Sanity Tests
    // ========================================================================

    #[test]
    fn test_all_vulnerability_patterns_compile_validly() {
        let patterns = compile_vulnerability_patterns();
        for (regex, _pattern_type, description) in &patterns {
            // Test that regex is valid by testing with a known matching string
            // Most patterns won't match empty string, so we just verify they don't panic
            let _ = regex.is_match("test");
            assert!(!description.is_empty());
        }
    }

    #[test]
    fn test_all_risky_patterns_compile_validly() {
        let patterns = compile_risky_patterns();
        for (regex, _pattern_type, risk_score) in &patterns {
            // Test that regex is valid - just verify they don't panic
            let _ = regex.is_match("test");
            assert!(*risk_score >= 0.0 && *risk_score <= 1.0);
        }
    }
}
