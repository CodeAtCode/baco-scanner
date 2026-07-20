//! Threat model file persistence operations.
//!
//! Provides save/load/parse/merge operations for threat model files
//! using YAML frontmatter + markdown body format.

use crate::analysis_context::AnalysisContext;
use crate::findings::VulnerabilityFinding;
use crate::threat_model::model::{ThreatModelFile, ThreatModelFrontmatter};
use std::fs;
use std::path::Path;

impl ThreatModelFile {
    /// Generate a threat model from analysis context and findings
    pub fn generate(context: &AnalysisContext, findings: &[VulnerabilityFinding]) -> Self {
        let mut high_risk_areas: Vec<String> = Vec::new();

        // Extract unique high-risk file paths from findings
        let mut seen_files = std::collections::HashSet::new();
        for finding in findings {
            if !seen_files.contains(&finding.file_path) {
                seen_files.insert(finding.file_path.clone());

                // Consider files with high severity as high risk
                let is_high_severity = matches!(
                    finding.severity,
                    crate::findings::Severity::High | crate::findings::Severity::Critical
                );

                if is_high_severity {
                    high_risk_areas.push(finding.file_path.clone());
                }
            }
        }

        // Generate markdown body from findings and context
        let body = Self::generate_markdown(context, findings);

        Self {
            frontmatter: ThreatModelFrontmatter {
                version: "1.0".to_string(),
                generated_at: chrono::Utc::now().to_rfc3339(),
                project_type: context.project_type.to_string(),
                total_threats: findings.len() as u32,
                high_risk_areas,
            },
            body,
        }
    }

    /// Generate markdown body from context and findings
    fn generate_markdown(context: &AnalysisContext, findings: &[VulnerabilityFinding]) -> String {
        let mut md = String::new();

        // Add threat model from context if available
        if let Some(ref threat_model) = context.threat_model {
            md.push_str("## Architecture Threat Model\n\n");
            md.push_str(threat_model);
            md.push_str("\n\n");
        }

        // Add findings summary
        md.push_str("## Findings Summary\n\n");
        md.push_str(&format!("Total findings: {}\n\n", findings.len()));

        if !findings.is_empty() {
            md.push_str("### Findings by Severity\n\n");

            let mut critical = Vec::new();
            let mut high = Vec::new();
            let mut medium = Vec::new();
            let mut low = Vec::new();

            for finding in findings {
                match finding.severity {
                    crate::findings::Severity::Critical => critical.push(finding),
                    crate::findings::Severity::High => high.push(finding),
                    crate::findings::Severity::Medium => medium.push(finding),
                    crate::findings::Severity::Low | crate::findings::Severity::Info => {
                        low.push(finding)
                    }
                }
            }

            if !critical.is_empty() {
                md.push_str("#### Critical\n");
                for f in &critical {
                    md.push_str(&format!(
                        "- **{}** in `{}` (L{})\n",
                        f.title,
                        f.file_path,
                        f.line_number.unwrap_or(0)
                    ));
                }
                md.push('\n');
            }

            if !high.is_empty() {
                md.push_str("#### High\n");
                for f in &high {
                    md.push_str(&format!(
                        "- **{}** in `{}` (L{})\n",
                        f.title,
                        f.file_path,
                        f.line_number.unwrap_or(0)
                    ));
                }
                md.push('\n');
            }

            if !medium.is_empty() {
                md.push_str("#### Medium\n");
                for f in &medium {
                    md.push_str(&format!(
                        "- **{}** in `{}` (L{})\n",
                        f.title,
                        f.file_path,
                        f.line_number.unwrap_or(0)
                    ));
                }
                md.push('\n');
            }

            if !low.is_empty() {
                md.push_str("#### Low/Info\n");
                for f in &low {
                    md.push_str(&format!(
                        "- **{}** in `{}` (L{})\n",
                        f.title,
                        f.file_path,
                        f.line_number.unwrap_or(0)
                    ));
                }
                md.push('\n');
            }
        }

        // Add recommendations section
        md.push_str("\n## Recommendations\n\n");
        md.push_str("- Review all critical and high severity findings first\n");
        md.push_str("- Implement defense in depth for authentication-critical paths\n");
        md.push_str("- Enable logging and monitoring for security-relevant events\n");

        md
    }

    /// Get the .baco/ directory path for a project
    fn baco_dir(path: &Path) -> std::io::Result<std::path::PathBuf> {
        let dir = path.join(".baco");
        Ok(dir)
    }

    /// Get the threat model file path
    fn threat_model_path(path: &Path) -> std::io::Result<std::path::PathBuf> {
        Ok(Self::baco_dir(path)?.join("threat_model.md"))
    }

    /// Save threat model to file at .baco/threat_model.md
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let dir = Self::baco_dir(path)?;
        fs::create_dir_all(&dir)?;

        let file_path = Self::threat_model_path(path)?;

        // Serialize frontmatter to YAML
        let frontmatter_yaml = serde_yaml::to_string(&self.frontmatter)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Write full file: YAML frontmatter + markdown body
        let content = format!(
            "---\n{}---\n\n{}",
            frontmatter_yaml.trim(),
            self.body.trim()
        );
        fs::write(file_path, content)?;

        tracing::info!("Threat model saved to .baco/threat_model.md");
        Ok(())
    }

    /// Load threat model from file
    pub fn load(path: &Path) -> std::io::Result<Option<ThreatModelFile>> {
        let file_path = Self::threat_model_path(path)?;

        match fs::read_to_string(&file_path) {
            Ok(content) => match Self::parse(&content) {
                Ok(tm) => Ok(Some(tm)),
                Err(e) => {
                    tracing::warn!("Corrupted threat model file: {}. Will regenerate.", e);
                    Ok(None)
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Parse a threat model file from string content
    #[cfg_attr(test, visibility::make(pub))]
    pub fn parse(content: &str) -> Result<Self, String> {
        let content = content.trim();

        if !content.starts_with("---") {
            return Err("Missing YAML frontmatter".to_string());
        }

        // Find closing --- marker
        let rest = &content[3..];
        let closing_idx = rest.find("---").ok_or("Missing closing --- marker")?;

        // The YAML ends right before the closing ---
        let mut yaml_str = &rest[..closing_idx];
        while yaml_str.ends_with('-') {
            yaml_str = &yaml_str[..yaml_str.len() - 1];
        }
        yaml_str = yaml_str.trim();

        // Body is everything after the closing ---
        let body = if closing_idx + 3 < rest.len() {
            rest[closing_idx + 3..].trim_start().to_string()
        } else {
            String::new()
        };

        let frontmatter: ThreatModelFrontmatter = serde_yaml::from_str(yaml_str)
            .map_err(|e| format!("Failed to parse YAML frontmatter: {}", e))?;

        Ok(Self { frontmatter, body })
    }

    /// Merge new threat model with existing one
    pub fn merge_with_existing(new: &ThreatModelFile, existing: &ThreatModelFile) -> Self {
        // Combine high risk areas from both
        let mut combined_risk: std::collections::HashSet<String> = std::collections::HashSet::new();
        for area in &new.frontmatter.high_risk_areas {
            combined_risk.insert(area.clone());
        }
        for area in &existing.frontmatter.high_risk_areas {
            combined_risk.insert(area.clone());
        }

        let mut high_risk_areas: Vec<String> = combined_risk.into_iter().collect();
        high_risk_areas.sort();

        // Take the newer body but merge key information
        let mut merged_body = String::new();
        merged_body.push_str("## Merged Threat Model\n\n");
        merged_body.push_str(&format!(
            "Previous scan: {}\n",
            existing.frontmatter.generated_at
        ));
        merged_body.push_str(&format!(
            "Current scan: {}\n\n",
            new.frontmatter.generated_at
        ));

        // Combine the bodies - use new as primary, note existing if different
        merged_body.push_str(&new.body);

        // Append a note about previous findings if significant
        if existing.frontmatter.total_threats > 0 {
            merged_body.push_str("\n## Previous Scan Summary\n\n");
            merged_body.push_str(&format!(
                "- Total threats found: {}\n",
                existing.frontmatter.total_threats
            ));
        }

        Self {
            frontmatter: ThreatModelFrontmatter {
                version: new.frontmatter.version.clone(),
                generated_at: new.frontmatter.generated_at.clone(),
                project_type: new.frontmatter.project_type.clone(),
                total_threats: new
                    .frontmatter
                    .total_threats
                    .max(existing.frontmatter.total_threats),
                high_risk_areas,
            },
            body: merged_body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn mock_context() -> AnalysisContext {
        AnalysisContext {
            project_type: crate::project_type::ProjectType::Web,
            architecture_summary: "Test architecture".to_string(),
            threat_model: Some("Mock threat model content".to_string()),
            invariants: vec!["test invariant".to_string()],
            findings_so_far: Vec::new(),
        }
    }

    fn mock_findings() -> Vec<VulnerabilityFinding> {
        vec![
            VulnerabilityFinding {
                id: "test-1".to_string(),
                title: "SQL Injection".to_string(),
                description: "SQLi in user input".to_string(),
                severity: crate::findings::Severity::Critical,
                confidence_score: 0.9,
                cwe_id: Some("CWE-89".to_string()),
                file_path: "src/db.rs".to_string(),
                line_number: Some(42),
                code_snippet: Some("query(user_input)".to_string()),
                diff_hunk: None,
                recommendation: Some("Use parameterized queries".to_string()),
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
            },
            VulnerabilityFinding {
                id: "test-2".to_string(),
                title: "XSS in Header".to_string(),
                description: "Cross-site scripting".to_string(),
                severity: crate::findings::Severity::High,
                confidence_score: 0.85,
                cwe_id: Some("CWE-79".to_string()),
                file_path: "src/handler.rs".to_string(),
                line_number: Some(100),
                code_snippet: Some("header.write(unsafe)".to_string()),
                diff_hunk: None,
                recommendation: Some("Escape output".to_string()),
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
            },
        ]
    }

    #[test]
    fn test_generate_threat_model() {
        let ctx = mock_context();
        let findings = mock_findings();

        let tm = ThreatModelFile::generate(&ctx, &findings);

        assert_eq!(tm.frontmatter.version, "1.0");
        assert_eq!(tm.frontmatter.project_type, "web");
        assert_eq!(tm.frontmatter.total_threats, 2);
        assert!(tm
            .frontmatter
            .high_risk_areas
            .contains(&"src/db.rs".to_string()));
        assert!(tm
            .frontmatter
            .high_risk_areas
            .contains(&"src/handler.rs".to_string()));
        assert!(tm.body.contains("SQL Injection"));
        assert!(tm.body.contains("XSS in Header"));
    }

    #[test]
    fn test_save_load_roundtrip() {
        let tmp = tempdir().unwrap();
        let ctx = mock_context();
        let findings = mock_findings();

        let original = ThreatModelFile::generate(&ctx, &findings);
        original.save(tmp.path()).unwrap();

        let loaded = ThreatModelFile::load(tmp.path()).unwrap();

        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.frontmatter.version, original.frontmatter.version);
        assert_eq!(
            loaded.frontmatter.project_type,
            original.frontmatter.project_type
        );
        assert_eq!(
            loaded.frontmatter.total_threats,
            original.frontmatter.total_threats
        );
        assert_eq!(loaded.body.trim(), original.body.trim());
    }

    #[test]
    fn test_load_nonexistent() {
        let tmp = tempdir().unwrap();
        let loaded = ThreatModelFile::load(tmp.path()).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_corrupted_file_handling() {
        let tmp = tempdir().unwrap();
        let baco_dir = tmp.path().join(".baco");
        std::fs::create_dir_all(&baco_dir).unwrap();

        // Write corrupted content
        let corrupt_path = baco_dir.join("threat_model.md");
        std::fs::write(&corrupt_path, "---invalid yaml!!\n---\n\nNot valid").unwrap();

        // Should return None, not panic
        let result = ThreatModelFile::load(tmp.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_merge_with_existing() {
        let ctx = mock_context();

        let mut existing = ThreatModelFile::generate(&ctx, &mock_findings()[0..1]);
        existing.frontmatter.generated_at = "2024-01-01T00:00:00Z".to_string();

        let mut new = ThreatModelFile::generate(&ctx, &mock_findings()[1..2]);
        new.frontmatter.generated_at = "2024-01-02T00:00:00Z".to_string();

        let merged = ThreatModelFile::merge_with_existing(&new, &existing);

        // Should have combined high risk areas
        assert!(merged
            .frontmatter
            .high_risk_areas
            .contains(&"src/db.rs".to_string()));
        assert!(merged
            .frontmatter
            .high_risk_areas
            .contains(&"src/handler.rs".to_string()));

        // Should have newer timestamp
        assert!(merged.frontmatter.generated_at.contains("2024-01-02"));

        // Should reference both scans
        assert!(merged.body.contains("Previous scan"));
    }

    #[test]
    fn test_default_frontmatter() {
        let fm = ThreatModelFrontmatter::default();

        assert_eq!(fm.version, "1.0");
        assert_eq!(fm.project_type, "unknown");
        assert_eq!(fm.total_threats, 0);
        assert!(fm.high_risk_areas.is_empty());
    }

    #[test]
    fn test_parse_valid_content() {
        let content = r#"---
version: "1.0"
generated_at: "2024-01-01T00:00:00Z"
project_type: web
total_threats: 5
high_risk_areas:
  - src/auth.rs
  - src/admin.rs
---

# Threat Model

This is the body content.
"#;

        let tm = ThreatModelFile::parse(content).unwrap();

        assert_eq!(tm.frontmatter.version, "1.0");
        assert_eq!(tm.frontmatter.total_threats, 5);
        assert_eq!(tm.body, "# Threat Model\n\nThis is the body content.");
    }

    #[test]
    fn test_parse_missing_frontmatter() {
        let content = "# Just markdown\nNo frontmatter";

        let result = ThreatModelFile::parse(content);
        assert!(result.is_err());
    }
}
