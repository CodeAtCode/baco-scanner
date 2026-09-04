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
    pub fn extract_directory(file_path: &str) -> String {
        if let Some(idx) = file_path.rfind('/') {
            file_path[..idx].to_string()
        } else {
            ".".to_string()
        }
    }

    /// Extract CWE number from optional CWE string (e.g., "CWE-89" -> "89")
    pub fn extract_cwe_number(cwe: &Option<String>) -> Option<&str> {
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
