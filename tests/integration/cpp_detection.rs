// C++ preset detection regression tests
//
// These tests verify that the bundled semgrep custom_rules in the
// cpp preset actually detect vulnerabilities in real C++ code.

#[cfg(test)]
mod tests {
    use baco::config::ScannerConfig;
    use baco::preset::load_preset;
    use baco::semgrep::SemgrepRunner;

    const VULNERABLE_FIXTURE: &str = "tests/fixtures/cpp_detection/vulnerable.cpp";
    const SAFE_FIXTURE: &str = "tests/fixtures/cpp_detection/safe.cpp";
    const EXPECTED_RULE_IDS: [&str; 5] = [
        "cpp-gets-critical",
        "cpp-strcpy-high",
        "cpp-memcpy-variable-size-high",
        "cpp-system-command-high",
        "cpp-printf-nonliteral-format-high",
    ];

    /// Check if semgrep binary is available on the system
    fn semgrep_available() -> bool {
        std::process::Command::new("semgrep")
            .arg("--version")
            .output()
            .is_ok()
    }

    /// Strip the temp-config prefix semgrep adds to rule IDs (e.g.
    /// "tmp.cpp-gets-critical") so assertions compare bare IDs.
    fn base_rule_id(full_id: &str) -> String {
        full_id.rsplit('.').next().unwrap_or(full_id).to_string()
    }

    /// Build a SemgrepRunner configured with the cpp preset's custom rules
    fn build_cpp_runner() -> SemgrepRunner {
        let overlay = load_preset("cpp").expect("cpp preset should load");
        let mut config = ScannerConfig::default();
        overlay.merge_into(&mut config);

        assert!(
            !config.scanner.semgrep.custom_rules.is_empty(),
            "cpp preset must ship custom_rules"
        );

        SemgrepRunner::new(vec![], vec![]).with_custom_rules(config.scanner.semgrep.custom_rules)
    }

    #[tokio::test]
    async fn vulnerable_fixture_matches_all_five_rules() {
        if !semgrep_available() {
            eprintln!("skipping: semgrep binary not installed");
            return;
        }

        let runner = build_cpp_runner();
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
    }

    #[tokio::test]
    async fn safe_fixture_has_zero_findings() {
        if !semgrep_available() {
            eprintln!("skipping: semgrep binary not installed");
            return;
        }

        let runner = build_cpp_runner();
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

        let runner = build_cpp_runner();
        let findings = runner
            .run(VULNERABLE_FIXTURE, "")
            .await
            .expect("semgrep scan should succeed");

        // Expected CWE mappings
        let expected_cwes = [
            ("cpp-gets-critical", "CWE-120"),
            ("cpp-strcpy-high", "CWE-120"),
            ("cpp-memcpy-variable-size-high", "CWE-120"),
            ("cpp-system-command-high", "CWE-78"),
            ("cpp-printf-nonliteral-format-high", "CWE-134"),
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

        let runner = build_cpp_runner();

        // semgrep's default ignore rules exclude paths under `tests/`, so the
        // fixtures are copied to a neutral temp directory to exercise real
        // directory scanning and multi-file result attribution.
        let dir = tempfile::Builder::new()
            .prefix("cpp_fixtures")
            .tempdir()
            .expect("temp dir should be created");
        std::fs::copy(VULNERABLE_FIXTURE, dir.path().join("vulnerable.cpp"))
            .expect("vulnerable fixture should copy");
        std::fs::copy(SAFE_FIXTURE, dir.path().join("safe.cpp")).expect("safe fixture should copy");

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
                finding.file_path.contains("vulnerable.cpp"),
                "finding for rule '{}' must reference the vulnerable file, got '{}'",
                finding.title,
                finding.file_path
            );
        }
    }
}
