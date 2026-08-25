//! Attack chain detection module: analyzes findings for cross-file/cross-CWE attack patterns

use crate::findings::VulnerabilityFinding;

/// Types of attack chains that can be detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainType {
    /// SQL injection + command injection = code execution chain
    InjectionToExecution,
    /// Authentication bypass + privilege escalation
    AuthBypassToPrivilegeEscal,
    /// Path traversal + file include/exec = RCE
    FileAccessToRCE,
    /// SSRF + data exfiltration
    DataExfilChain,
}

/// Result of attack chain analysis
#[derive(Debug, Clone)]
pub struct ChainResult {
    /// Primary finding ID (the initiating vulnerability)
    pub primary_finding_id: String,
    /// Partner finding IDs that complete the chain
    pub partner_finding_ids: Vec<String>,
    /// Human-readable description of the chain
    pub chain_description: String,
    /// Type of attack chain
    pub chain_type: ChainType,
}

/// Analyzer for detecting attack chains across findings
pub struct ChainAnalyzer;

impl ChainAnalyzer {
    /// Known CWE combinations for InjectionToExecution chains
    /// Maps (CWE1, CWE2) pairs that indicate injection-to-execution
    const INJECTION_EXEC_PAIRS: &'static [(&'static str, &'static str)] = &[
        ("89", "78"), // SQLi + Command Injection
        ("89", "94"), // SQLi + Code Injection
        ("78", "94"), // Command Injection + Code Injection
        ("91", "78"), // XML Injection + Command Injection
    ];

    /// Known CWE combinations for AuthBypassToPrivilegeEscal chains
    const AUTH_PRIVESC_PAIRS: &'static [(&'static str, &'static str)] = &[
        ("287", "269"), // Auth Bypass + Privilege Escalation
        ("287", "284"), // Auth Bypass + Improper Access Control
        ("639", "269"), // Authorization Bypass + Privilege Escalation
        ("287", "427"), // Auth Bypass + Uncontrolled Search Path
    ];

    /// Known CWE combinations for FileAccessToRCE chains
    const FILE_RCE_PAIRS: &'static [(&'static str, &'static str)] = &[
        ("22", "98"), // Path Traversal + File Include
        ("22", "78"), // Path Traversal + Command Injection
        ("73", "98"), // External Control of File Name + File Include
        ("23", "98"), // Relative Path Traversal + File Include
    ];

    /// Known CWE combinations for DataExfilChain
    const DATA_EXFIL_PAIRS: &'static [(&'static str, &'static str)] = &[
        ("918", "200"), // SSRF + Information Exposure
        ("918", "532"), // SSRF + Information Exposure via Log
        ("918", "209"), // SSRF + Information Exposure via Error
        ("502", "200"), // Deserialization + Info Exposure
    ];

    /// Analyze findings for attack chains across files and CWEs
    ///
    /// Groups findings by file proximity and looks for known attack patterns
    pub fn analyze_chains(findings: &[VulnerabilityFinding]) -> Vec<ChainResult> {
        if findings.is_empty() {
            return Vec::new();
        }

        let mut chains = Vec::new();

        // Group findings by directory for proximity analysis
        let by_dir = Self::group_by_directory(findings);

        // Check each group for attack chains
        for (_dir, group_findings) in by_dir {
            if group_findings.len() < 2 {
                continue;
            }

            // Check for injection-to-execution chains
            if let Some(chain) = Self::find_injection_exec_chain(&group_findings) {
                chains.push(chain);
            }

            // Check for auth bypass to privilege escalation chains
            if let Some(chain) = Self::find_auth_privesc_chain(&group_findings) {
                chains.push(chain);
            }

            // Check for file access to RCE chains
            if let Some(chain) = Self::find_file_rce_chain(&group_findings) {
                chains.push(chain);
            }

            // Check for data exfiltration chains
            if let Some(chain) = Self::find_data_exfil_chain(&group_findings) {
                chains.push(chain);
            }
        }

        chains
    }

    /// Group findings by directory path
    fn group_by_directory(
        findings: &[VulnerabilityFinding],
    ) -> std::collections::HashMap<String, Vec<&VulnerabilityFinding>> {
        let mut groups: std::collections::HashMap<String, Vec<&VulnerabilityFinding>> =
            std::collections::HashMap::new();

        for finding in findings {
            let dir = Self::extract_directory(&finding.file_path);
            groups.entry(dir).or_default().push(finding);
        }

        groups
    }

    /// Extract directory from file path
    fn extract_directory(file_path: &str) -> String {
        if let Some(idx) = file_path.rfind('/') {
            file_path[..idx].to_string()
        } else {
            ".".to_string()
        }
    }

    /// Extract CWE number from optional CWE string (e.g., "CWE-89" -> "89")
    fn extract_cwe_number(cwe: &Option<String>) -> Option<&str> {
        cwe.as_ref()
            .and_then(|s| s.find('-').map(|idx| &s[idx + 1..]))
    }

    /// Check if two CWEs form a pair against the given pairs table
    fn is_cwe_pair(pairs: &[(&str, &str)], cwe1: &Option<String>, cwe2: &Option<String>) -> bool {
        let num1 = Self::extract_cwe_number(cwe1);
        let num2 = Self::extract_cwe_number(cwe2);

        if let (Some(n1), Some(n2)) = (num1, num2) {
            pairs
                .iter()
                .any(|&(a, b)| (a == n1 && b == n2) || (a == n2 && b == n1))
        } else {
            false
        }
    }

    /// Find a chain in a group of findings using the given pair checker and chain type
    fn find_chain<F>(
        findings: &[&VulnerabilityFinding],
        pair_checker: F,
        chain_type: ChainType,
    ) -> Option<ChainResult>
    where
        F: Fn(&Option<String>, &Option<String>) -> bool + Copy,
    {
        for (i, f1) in findings.iter().enumerate() {
            for f2 in findings.iter().skip(i + 1) {
                if pair_checker(&f1.cwe_id, &f2.cwe_id) {
                    let description = match chain_type {
                        ChainType::InjectionToExecution => {
                            format!(
                                "Injection-to-execution chain: {} ({} → {})",
                                f1.file_path,
                                f1.cwe_id.as_deref().unwrap_or("unknown"),
                                f2.cwe_id.as_deref().unwrap_or("unknown")
                            )
                        }
                        ChainType::AuthBypassToPrivilegeEscal => {
                            format!(
                                "Auth bypass to privilege escalation: {} ({} → {})",
                                f1.file_path,
                                f1.cwe_id.as_deref().unwrap_or("unknown"),
                                f2.cwe_id.as_deref().unwrap_or("unknown")
                            )
                        }
                        ChainType::FileAccessToRCE => {
                            format!(
                                "File access to RCE: {} ({} → {})",
                                f1.file_path,
                                f1.cwe_id.as_deref().unwrap_or("unknown"),
                                f2.cwe_id.as_deref().unwrap_or("unknown")
                            )
                        }
                        ChainType::DataExfilChain => {
                            format!(
                                "Data exfiltration chain: {} ({} → {})",
                                f1.file_path,
                                f1.cwe_id.as_deref().unwrap_or("unknown"),
                                f2.cwe_id.as_deref().unwrap_or("unknown")
                            )
                        }
                    };
                    return Some(ChainResult {
                        primary_finding_id: f1.id.clone(),
                        partner_finding_ids: vec![f2.id.clone()],
                        chain_description: description,
                        chain_type,
                    });
                }
            }
        }
        None
    }

    /// Find injection-to-execution chain in a group of findings
    fn find_injection_exec_chain(findings: &[&VulnerabilityFinding]) -> Option<ChainResult> {
        Self::find_chain(
            findings,
            |cwe1, cwe2| Self::is_cwe_pair(Self::INJECTION_EXEC_PAIRS, cwe1, cwe2),
            ChainType::InjectionToExecution,
        )
    }

    /// Find auth bypass to privilege escalation chain
    fn find_auth_privesc_chain(findings: &[&VulnerabilityFinding]) -> Option<ChainResult> {
        Self::find_chain(
            findings,
            |cwe1, cwe2| Self::is_cwe_pair(Self::AUTH_PRIVESC_PAIRS, cwe1, cwe2),
            ChainType::AuthBypassToPrivilegeEscal,
        )
    }

    /// Find file access to RCE chain
    fn find_file_rce_chain(findings: &[&VulnerabilityFinding]) -> Option<ChainResult> {
        Self::find_chain(
            findings,
            |cwe1, cwe2| Self::is_cwe_pair(Self::FILE_RCE_PAIRS, cwe1, cwe2),
            ChainType::FileAccessToRCE,
        )
    }

    /// Find data exfiltration chain
    fn find_data_exfil_chain(findings: &[&VulnerabilityFinding]) -> Option<ChainResult> {
        Self::find_chain(
            findings,
            |cwe1, cwe2| Self::is_cwe_pair(Self::DATA_EXFIL_PAIRS, cwe1, cwe2),
            ChainType::DataExfilChain,
        )
    }
}

/// Apply chain verdicts to findings, marking those involved in attack chains
pub fn apply_chain_verdicts(findings: &mut [VulnerabilityFinding], chains: &[ChainResult]) {
    use crate::findings::TriageVerdict;

    // Build a map of finding IDs to their chain partners
    let mut chain_partners: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for chain in chains {
        // Add partners to primary finding
        chain_partners
            .entry(chain.primary_finding_id.clone())
            .or_default()
            .extend(chain.partner_finding_ids.clone());

        // Add primary to each partner's list
        for partner_id in &chain.partner_finding_ids {
            chain_partners
                .entry(partner_id.clone())
                .or_default()
                .push(chain.primary_finding_id.clone());
        }
    }

    // Update findings with chain verdicts
    for finding in findings {
        if let Some(partners) = chain_partners.get(&finding.id) {
            if !partners.is_empty() {
                finding.triage_verdict = Some(TriageVerdict::ChainRequired {
                    chain_partner_ids: partners.clone(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Severity, TriageVerdict};

    fn create_finding(id: &str, file_path: &str, cwe_id: Option<&str>) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: id.to_string(),
            title: "Test finding".to_string(),
            description: "Test description".to_string(),
            severity: Severity::High,
            confidence_score: 0.8,
            cwe_id: cwe_id.map(|s| s.to_string()),
            file_path: file_path.to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["test".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
            evidence: vec![],
            verification_tier: None,
        }
    }

    #[test]
    fn test_analyze_chains_empty_findings() {
        let findings: Vec<VulnerabilityFinding> = Vec::new();
        let chains = ChainAnalyzer::analyze_chains(&findings);
        assert!(chains.is_empty());
    }

    #[test]
    fn test_analyze_chains_single_finding() {
        let findings = vec![create_finding("f1", "src/main.rs", Some("CWE-89"))];
        let chains = ChainAnalyzer::analyze_chains(&findings);
        assert!(chains.is_empty());
    }

    #[test]
    fn test_injection_to_execution_chain() {
        let findings = vec![
            create_finding("f1", "src/db.rs", Some("CWE-89")), // SQLi
            create_finding("f2", "src/db.rs", Some("CWE-78")), // Command Injection
        ];
        let chains = ChainAnalyzer::analyze_chains(&findings);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].chain_type, ChainType::InjectionToExecution);
        assert_eq!(chains[0].primary_finding_id, "f1");
        assert_eq!(chains[0].partner_finding_ids, vec!["f2"]);
    }

    #[test]
    fn test_auth_bypass_to_privilege_escalation() {
        let findings = vec![
            create_finding("f1", "src/auth.rs", Some("CWE-287")), // Auth Bypass
            create_finding("f2", "src/admin.rs", Some("CWE-269")), // Privilege Escalation
        ];
        let chains = ChainAnalyzer::analyze_chains(&findings);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].chain_type, ChainType::AuthBypassToPrivilegeEscal);
    }

    #[test]
    fn test_file_access_to_rce() {
        let findings = vec![
            create_finding("f1", "src/upload.rs", Some("CWE-22")), // Path Traversal
            create_finding("f2", "src/include.rs", Some("CWE-98")), // File Include
        ];
        let chains = ChainAnalyzer::analyze_chains(&findings);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].chain_type, ChainType::FileAccessToRCE);
    }

    #[test]
    fn test_data_exfiltration_chain() {
        let findings = vec![
            create_finding("f1", "src/proxy.rs", Some("CWE-918")), // SSRF
            create_finding("f2", "src/api.rs", Some("CWE-200")),   // Info Exposure
        ];
        let chains = ChainAnalyzer::analyze_chains(&findings);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].chain_type, ChainType::DataExfilChain);
    }

    #[test]
    fn test_no_chain_different_directories() {
        let findings = vec![
            create_finding("f1", "src/db.rs", Some("CWE-89")), // SQLi in src/
            create_finding("f2", "tests/test.rs", Some("CWE-78")), // Command Injection in tests/
        ];
        let chains = ChainAnalyzer::analyze_chains(&findings);
        // Different directories, no chain detected
        assert!(chains.is_empty());
    }

    #[test]
    fn test_apply_chain_verdicts() {
        let mut findings = vec![
            create_finding("f1", "src/db.rs", Some("CWE-89")),
            create_finding("f2", "src/db.rs", Some("CWE-78")),
            create_finding("f3", "src/other.rs", Some("CWE-200")),
        ];

        let chains = vec![ChainResult {
            primary_finding_id: "f1".to_string(),
            partner_finding_ids: vec!["f2".to_string()],
            chain_description: "Test chain".to_string(),
            chain_type: ChainType::InjectionToExecution,
        }];

        apply_chain_verdicts(&mut findings, &chains);

        // f1 and f2 should have ChainRequired verdict
        assert!(matches!(
            findings[0].triage_verdict,
            Some(TriageVerdict::ChainRequired { .. })
        ));
        assert!(matches!(
            findings[1].triage_verdict,
            Some(TriageVerdict::ChainRequired { .. })
        ));
        // f3 should have no verdict
        assert!(findings[2].triage_verdict.is_none());
    }

    #[test]
    fn test_extract_directory() {
        assert_eq!(
            ChainAnalyzer::extract_directory("src/db.rs"),
            "src".to_string()
        );
        assert_eq!(
            ChainAnalyzer::extract_directory("src/utils/db.rs"),
            "src/utils".to_string()
        );
        assert_eq!(ChainAnalyzer::extract_directory("main.rs"), ".".to_string());
    }

    #[test]
    fn test_extract_cwe_number() {
        assert_eq!(
            ChainAnalyzer::extract_cwe_number(&Some("CWE-89".to_string())),
            Some("89")
        );
        assert_eq!(
            ChainAnalyzer::extract_cwe_number(&Some("CWE-1234".to_string())),
            Some("1234")
        );
        assert_eq!(ChainAnalyzer::extract_cwe_number(&None), None);
    }

    #[test]
    fn test_chain_description_format() {
        let findings = vec![
            create_finding("f1", "src/db.rs", Some("CWE-89")),
            create_finding("f2", "src/db.rs", Some("CWE-78")),
        ];
        let chains = ChainAnalyzer::analyze_chains(&findings);
        assert!(chains[0].chain_description.contains("src/db.rs"));
        assert!(chains[0].chain_description.contains("CWE-89"));
        assert!(chains[0].chain_description.contains("CWE-78"));
    }
}
