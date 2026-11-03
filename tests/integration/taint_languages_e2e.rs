//! Integration tests for taint rule detection across multiple languages.
//!
//! These tests verify that the bundled taint rules actually detect vulnerabilities
//! when run against real code via the semgrep binary.
//!
//! Note: These tests require the semgrep binary to be installed. If semgrep is
//! not found, the tests will print a skip message and pass (not fail).

use baco::semgrep::SemgrepRunner;

#[test]
fn test_taint_languages_e2e() {
    // List of languages to test with their fixture paths and expected rule suffixes
    let test_cases = vec![
        (
            "php",
            "tests/fixtures/taint/php/vulnerable.php",
            "php-taint-sqli-high",
        ),
        (
            "c",
            "tests/fixtures/taint/c/vulnerable.c",
            "c-taint-cmdi-high",
        ),
        (
            "java",
            "tests/fixtures/taint/java/Vulnerable.java",
            "java-taint-sqli-high",
        ),
        (
            "ruby",
            "tests/fixtures/taint/ruby/vulnerable.rb",
            "ruby-taint-sqli-high",
        ),
        (
            "csharp",
            "tests/fixtures/taint/csharp/Vulnerable.cs",
            "csharp-sqli",
        ),
    ];

    for (lang, fixture_path, expected_rule_suffix) in test_cases {
        // Check if semgrep is available
        let semgrep_exists = std::process::Command::new("semgrep")
            .arg("--version")
            .output()
            .is_ok();

        if !semgrep_exists {
            println!(
                "SKIP: semgrep binary not found - skipping {} taint e2e test",
                lang
            );
            continue;
        }

        // Create runner with the language
        let runner = SemgrepRunner::new(vec![], vec![])
            .with_languages(vec![lang.to_string()])
            .with_timeout(30);

        // Run semgrep on the fixture file
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create runtime");

        let result = runtime.block_on(runner.run(fixture_path, ""));

        match result {
            Ok(findings) => {
                if findings.is_empty() {
                    panic!(
                        "No findings for {} - expected to find rule ending with '{}'",
                        lang, expected_rule_suffix
                    );
                }

                // Check that at least one finding matches the expected rule
                // The title field contains the check_id
                let found_expected = findings
                    .iter()
                    .any(|f| f.title.contains(expected_rule_suffix));

                if !found_expected {
                    let found_ids: Vec<String> = findings.iter().map(|f| f.title.clone()).collect();
                    panic!(
                        "Found findings for {} but none matched rule '{}'. Found: {:?}",
                        lang, expected_rule_suffix, found_ids
                    );
                }

                println!(
                    "PASS: {} taint e2e test - found {} findings including '{}'",
                    lang,
                    findings.len(),
                    expected_rule_suffix
                );
            }
            Err(e) => {
                // If semgrep failed, check if it's a "not found" error
                if e.contains("not found") {
                    println!("SKIP: semgrep not found for {} - skipping test", lang);
                } else {
                    panic!("semgrep run failed for {}: {}", lang, e);
                }
            }
        }
    }
}
