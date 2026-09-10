// WordPress preset detection regression tests
//
// These tests verify that the bundled semgrep custom_rules in the
// wordpress-plugin preset actually detect vulnerabilities in real PHP code.

#[cfg(test)]
mod tests {
    use baco::config::ScannerConfig;
    use baco::preset::load_preset;
    use baco::semgrep::SemgrepRunner;

    const VULNERABLE_FIXTURE: &str = "tests/fixtures/wp_detection/vulnerable_dispatch.php";
    const SAFE_FIXTURE: &str = "tests/fixtures/wp_detection/safe_dispatch.php";
    const EXPECTED_RULE_IDS: [&str; 4] = [
        "wp-superglobal-file-read-high",
        "wp-open-redirect-superglobal-medium",
        "wp-ajax-dispatch-missing-nonce-high",
        "php-weak-hash-md5-medium",
    ];

    /// Check if semgrep binary is available on the system
    fn semgrep_available() -> bool {
        std::process::Command::new("semgrep")
            .arg("--version")
            .output()
            .is_ok()
    }

    /// Strip the temp-config prefix semgrep adds to rule IDs (e.g.
    /// "tmp.wp-superglobal-file-read-high") so assertions compare bare IDs.
    fn base_rule_id(full_id: &str) -> String {
        full_id.rsplit('.').next().unwrap_or(full_id).to_string()
    }

    /// Build a SemgrepRunner configured with the wordpress-plugin preset's custom rules
    fn build_wordpress_runner() -> SemgrepRunner {
        let overlay = load_preset("wordpress-plugin").expect("wordpress-plugin preset should load");
        let mut config = ScannerConfig::default();
        overlay.merge_into(&mut config);

        assert!(
            !config.scanner.semgrep.custom_rules.is_empty(),
            "wordpress-plugin preset must ship custom_rules"
        );

        SemgrepRunner::new(vec![], vec![]).with_custom_rules(config.scanner.semgrep.custom_rules)
    }

    #[tokio::test]
    async fn vulnerable_fixture_matches_all_four_rules() {
        if !semgrep_available() {
            eprintln!("skipping: semgrep binary not installed");
            return;
        }

        let runner = build_wordpress_runner();
        let findings = runner
            .run(VULNERABLE_FIXTURE, "")
            .await
            .expect("semgrep scan should succeed");

        // Assert at least one finding for each rule ID
        for rule_id in &EXPECTED_RULE_IDS {
            let matching: Vec<_> = findings
                .iter()
                .filter(|f| base_rule_id(&f.title) == *rule_id)
                .collect();

            assert!(
                !matching.is_empty(),
                "vulnerable fixture must match rule '{rule_id}' (found {} findings with matching base ID)",
                findings.iter().filter(|f| base_rule_id(&f.title).contains(rule_id)).count()
            );
        }

        // Assert severity levels for high and medium rules
        let high_rules = [
            "wp-superglobal-file-read-high",
            "wp-ajax-dispatch-missing-nonce-high",
        ];
        let medium_rules = [
            "wp-open-redirect-superglobal-medium",
            "php-weak-hash-md5-medium",
        ];

        for rule_id in &high_rules {
            let findings_for_rule: Vec<_> = findings
                .iter()
                .filter(|f| base_rule_id(&f.title) == *rule_id)
                .collect();

            for finding in findings_for_rule {
                assert!(
                    finding.severity == baco::findings::Severity::High
                        || finding.severity == baco::findings::Severity::Critical,
                    "rule '{rule_id}' must have high or critical severity, got {:?}",
                    finding.severity
                );
            }
        }

        for rule_id in &medium_rules {
            let findings_for_rule: Vec<_> = findings
                .iter()
                .filter(|f| base_rule_id(&f.title) == *rule_id)
                .collect();

            for finding in findings_for_rule {
                assert!(
                    finding.severity == baco::findings::Severity::Medium
                        || finding.severity == baco::findings::Severity::High,
                    "rule '{rule_id}' must have medium or higher severity, got {:?}",
                    finding.severity
                );
            }
        }
    }

    #[tokio::test]
    async fn safe_fixture_has_zero_findings() {
        if !semgrep_available() {
            eprintln!("skipping: semgrep binary not installed");
            return;
        }

        let runner = build_wordpress_runner();
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

    #[tokio::test]
    async fn cwe_metadata_survives_to_findings() {
        if !semgrep_available() {
            eprintln!("skipping: semgrep binary not installed");
            return;
        }

        let runner = build_wordpress_runner();
        let findings = runner
            .run(VULNERABLE_FIXTURE, "")
            .await
            .expect("semgrep scan should succeed");

        // Expected CWE mappings
        let expected_cwes = [
            ("wp-superglobal-file-read-high", "CWE-22"),
            ("wp-open-redirect-superglobal-medium", "CWE-601"),
            ("wp-ajax-dispatch-missing-nonce-high", "CWE-352"),
            ("php-weak-hash-md5-medium", "CWE-327"),
        ];

        for (rule_id, expected_cwe) in &expected_cwes {
            let matching: Vec<_> = findings
                .iter()
                .filter(|f| base_rule_id(&f.title) == *rule_id)
                .collect();

            assert!(
                !matching.is_empty(),
                "rule '{rule_id}' must have at least one finding"
            );

            for finding in matching {
                let cwe_present = finding
                    .cwe_id
                    .as_ref()
                    .map(|cwe| cwe.contains(expected_cwe))
                    .unwrap_or(false);

                assert!(
                    cwe_present,
                    "rule '{rule_id}' must have CWE '{expected_cwe}' in cwe_id, got {:?}",
                    finding.cwe_id
                );
            }
        }
    }

    #[tokio::test]
    async fn directory_scan_attributes_findings_to_vulnerable_file_only() {
        if !semgrep_available() {
            eprintln!("skipping: semgrep binary not installed");
            return;
        }

        let runner = build_wordpress_runner();

        // semgrep's default ignore rules exclude paths under `tests/`, so the
        // fixtures are copied to a neutral temp directory to exercise real
        // directory scanning and multi-file result attribution.
        let dir = tempfile::Builder::new()
            .prefix("wp_fixtures")
            .tempdir()
            .expect("temp dir should be created");
        std::fs::copy(
            VULNERABLE_FIXTURE,
            dir.path().join("vulnerable_dispatch.php"),
        )
        .expect("vulnerable fixture should copy");
        std::fs::copy(SAFE_FIXTURE, dir.path().join("safe_dispatch.php"))
            .expect("safe fixture should copy");

        let target = dir.path().to_str().expect("temp dir path should be utf-8");
        let findings = runner
            .run(target, "")
            .await
            .expect("semgrep scan should succeed");

        for rule_id in &EXPECTED_RULE_IDS {
            let matching: Vec<_> = findings
                .iter()
                .filter(|f| base_rule_id(&f.title) == *rule_id)
                .collect();

            assert!(
                !matching.is_empty(),
                "directory scan must detect rule '{rule_id}'"
            );
        }

        for finding in &findings {
            assert!(
                finding.file_path.contains("vulnerable_dispatch"),
                "finding for rule '{}' must reference the vulnerable file, got '{}'",
                finding.title,
                finding.file_path
            );
        }
    }
}
