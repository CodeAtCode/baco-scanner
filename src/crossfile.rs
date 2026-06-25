use crate::findings::VulnerabilityFinding;

pub struct CrossFileAnalyzer;

impl CrossFileAnalyzer {
    pub fn analyze_cross_file_references(
        findings: &[VulnerabilityFinding],
    ) -> Vec<VulnerabilityFinding> {
        let mut updated = findings.to_vec();

        for finding in &mut updated {
            let related = Self::find_related_findings(finding, findings);
            if !related.is_empty() {
                finding.cross_file_references =
                    Some(related.iter().map(|r| r.id.clone()).collect());
            }
        }

        updated
    }

    fn find_related_findings(
        current: &VulnerabilityFinding,
        all: &[VulnerabilityFinding],
    ) -> Vec<VulnerabilityFinding> {
        all.iter()
            .filter(|f| {
                // Must be in a different file
                f.file_path != current.file_path &&
                // Match on CWE ID (same vulnerability type)
                (current.cwe_id.as_ref().is_some_and(|cwe| f.cwe_id.as_ref() == Some(cwe)) ||
                 // Or match on severity AND same source
                 (f.severity == current.severity &&
                  !f.sources.is_empty() &&
                  f.sources.iter().any(|s| current.sources.contains(s))))
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

    #[test]
    fn test_cross_file_analysis() {
        let findings = vec![];
        let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);
        assert!(result.is_empty());
    }

    #[test]
    fn test_analyze_with_findings() {
        let findings = vec![VulnerabilityFinding {
            id: "test1".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity: Severity::High,
            confidence_score: 0.8,
            cwe_id: None,
            file_path: "src/main.c".to_string(),
            line_number: Some(10),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: Some(vec!["src/utils.c".to_string()]),
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
        }];

        let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);
        assert_eq!(result.len(), 1);
    }
}
