use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};

pub struct ConfidenceCalculator;

impl ConfidenceCalculator {
    pub fn calculate_composite(finding: &mut VulnerabilityFinding) -> f32 {
        // Base confidence score based on severity (0-100 scale)
        let base_score: f32 = match finding.severity {
            Severity::Critical => 80.0,
            Severity::High => 60.0,
            Severity::Medium => 40.0,
            Severity::Low => 20.0,
            Severity::Info => 10.0,
        };

        let mut score = base_score;

        // Add base confidence for having any source
        if !finding.sources.is_empty() {
            score += 10.0;
        }

        if finding.commit_reference.is_some() {
            score += 10.0;
        }

        if finding.ticket_reference.is_some() {
            score += 10.0;
        }

        if finding.sources.len() > 1 {
            score += 15.0;
        }

        // Boost for high/critical severity
        if finding.severity.is_high_or_critical() {
            score += 5.0;
        }

        // Verification status boost
        if let Some(VerificationStatus::Confirmed) = finding.verification_status {
            score += 20.0;
        }

        score.clamp(0.0, 100.0)
    }

    pub fn recalculate_priority(finding: &mut VulnerabilityFinding) {
        let confidence = Self::calculate_composite(finding);
        finding.confidence_score = confidence;
        let severity_multiplier = match finding.severity {
            Severity::Critical => 1.0,
            Severity::High => 0.8,
            Severity::Medium => 0.6,
            Severity::Low => 0.4,
            Severity::Info => 0.2,
        };

        finding.priority_score = Some(confidence * severity_multiplier);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_composite_confidence() {
        let mut finding = VulnerabilityFinding {
            id: "test".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity: Severity::High,
            confidence_score: 0.7,
            cwe_id: None,
            file_path: "test.c".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
        };

        let score = ConfidenceCalculator::calculate_composite(&mut finding);
        assert!(score >= 70.0);
        assert!(score <= 100.0);
    }

    #[test]
    fn test_confidence_with_multiple_sources() {
        let mut finding = VulnerabilityFinding {
            id: "test".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity: Severity::Critical,
            confidence_score: 0.5,
            cwe_id: None,
            file_path: "test.c".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string(), "llm".to_string()],
            commit_reference: Some("abc123".to_string()),
            ticket_reference: Some("SEC-123".to_string()),
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
        };

        let score = ConfidenceCalculator::calculate_composite(&mut finding);
        assert!(score > 0.9);
    }

    #[test]
    fn test_recalculate_priority() {
        let mut finding = VulnerabilityFinding {
            id: "test".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity: Severity::Critical,
            confidence_score: 0.8,
            cwe_id: None,
            file_path: "test.c".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
        };

        ConfidenceCalculator::recalculate_priority(&mut finding);
        assert!(finding.priority_score.is_some());
        assert!(finding.priority_score.unwrap() > 0.7);
    }
}
