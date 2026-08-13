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
