// Lane 4: Class C method-call sink e2e regression tests
//
// These tests verify that the php preset's custom rules detect
// template rendering sinks (CWE-79/95) in PHP code.

#[cfg(test)]
mod tests {
    use baco::config::ScannerConfig;
    use baco::findings::Severity;
    use baco::preset::load_preset;
    use baco::semgrep::SemgrepRunner;

    const VULNERABLE_FIXTURE: &str = "tests/fixtures/lane4/class_c_method_call_sink.php";
    const SAFE_FIXTURE: &str = "tests/fixtures/lane4/class_c_safe.php";
    const EXPECTED_RULE_ID: &str = "php-template-render-sink-high";

    /// Check if semgrep binary is available on the system
    fn semgrep_available() -> bool {
        std::process::Command::new("semgrep")
            .arg("--version")
            .output()
            .is_ok()
    }

    /// Strip the temp-config prefix semgrep adds to rule IDs (e.g.
    /// "tmp.php-template-render-sink-high") so assertions compare bare IDs.
    fn base_rule_id(full_id: &str) -> String {
        full_id.rsplit('.').next().unwrap_or(full_id).to_string()
    }

    /// Build a SemgrepRunner configured with the php preset's custom rules
    fn build_php_runner() -> SemgrepRunner {
        let overlay = load_preset("php").expect("php preset should load");
        let mut config = ScannerConfig::default();
        overlay.merge_into(&mut config);

        assert!(
            !config.scanner.semgrep.custom_rules.is_empty(),
            "php preset must ship custom_rules"
        );

        SemgrepRunner::new(vec![], vec![]).with_custom_rules(config.scanner.semgrep.custom_rules)
    }

    #[tokio::test]
    async fn vulnerable_fixture_detects_template_render_sink() {
        if !semgrep_available() {
            eprintln!("skipping: semgrep binary not installed");
            return;
        }

        let runner = build_php_runner();
        let findings = runner
            .run(VULNERABLE_FIXTURE, "")
            .await
            .expect("semgrep scan should succeed");

        // Assert at least one finding for the expected rule
        let matching: Vec<_> = findings
            .iter()
            .filter(|f| base_rule_id(&f.title) == EXPECTED_RULE_ID)
            .collect();

        assert!(
            !matching.is_empty(),
            "vulnerable fixture must match rule '{EXPECTED_RULE_ID}' (found {} findings)",
            findings
                .iter()
                .filter(|f| base_rule_id(&f.title).contains(EXPECTED_RULE_ID))
                .count()
        );

        // Assert CWE contains CWE-79 or CWE-95
        for finding in &matching {
            let cwe_present = finding
                .cwe_id
                .as_ref()
                .map(|cwe| cwe.contains("CWE-79") || cwe.contains("CWE-95"))
                .unwrap_or(false);

            assert!(
                cwe_present,
                "rule '{EXPECTED_RULE_ID}' must have CWE-79 or CWE-95 in cwe_id, got {:?}",
                finding.cwe_id
            );

            // Assert severity is High or Critical
            assert!(
                finding.severity == Severity::High || finding.severity == Severity::Critical,
                "rule '{EXPECTED_RULE_ID}' must have high or critical severity, got {:?}",
                finding.severity
            );
        }
    }

    #[tokio::test]
    async fn safe_fixture_has_zero_findings() {
        if !semgrep_available() {
            eprintln!("skipping: semgrep binary not installed");
            return;
        }

        let runner = build_php_runner();
        let findings = runner
            .run(SAFE_FIXTURE, "")
            .await
            .expect("semgrep scan should succeed");

        assert!(
            findings.is_empty(),
            "safe fixture must have zero findings, got {} findings",
            findings.len()
        );
    }
}
