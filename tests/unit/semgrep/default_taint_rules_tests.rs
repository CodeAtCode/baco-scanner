//! Tests for default taint-mode rules derived from project languages.
//!
//! When `SemgrepRunner.custom_rules` is empty, baco automatically applies
//! default taint-mode rules for Python, JavaScript/TypeScript, and Go projects.
//! This ensures data-flow vulnerabilities (SQLi, command injection, path traversal)
//! are detected by default without requiring manual preset selection.

use baco::semgrep::SemgrepRunner;

#[test]
fn test_default_taint_rules_for_python() {
    let runner = SemgrepRunner::new(vec![], vec![]).with_languages(vec!["python".to_string()]);

    let defaults = runner.derive_default_custom_rules();
    assert_eq!(
        defaults.len(),
        1,
        "Python should produce exactly one taint rules file"
    );

    let content = &defaults[0];
    assert!(content.contains("mode: taint"), "should contain taint mode");
    assert!(content.contains("CWE-89"), "should contain CWE-89 (SQLi)");
    assert!(
        content.contains("py-taint-sqli-high"),
        "should contain SQLi rule id"
    );
    assert!(
        content.contains("py-taint-cmdi-high"),
        "should contain command injection rule id"
    );
    assert!(
        content.contains("py-taint-path-traversal-high"),
        "should contain path traversal rule id"
    );
}

#[test]
fn test_default_taint_rules_for_javascript() {
    let runner = SemgrepRunner::new(vec![], vec![]).with_languages(vec!["javascript".to_string()]);

    let defaults = runner.derive_default_custom_rules();
    assert_eq!(
        defaults.len(),
        1,
        "JavaScript should produce exactly one taint rules file"
    );

    let content = &defaults[0];
    assert!(content.contains("mode: taint"), "should contain taint mode");
    assert!(
        content.contains("js-taint-sqli-high"),
        "should contain JS SQLi rule id"
    );
    assert!(
        content.contains("CWE-78"),
        "should contain CWE-78 (command injection)"
    );
}

#[test]
fn test_default_taint_rules_for_typescript() {
    let runner = SemgrepRunner::new(vec![], vec![]).with_languages(vec!["typescript".to_string()]);

    let defaults = runner.derive_default_custom_rules();
    assert_eq!(
        defaults.len(),
        1,
        "TypeScript should produce exactly one taint rules file"
    );

    let content = &defaults[0];
    assert!(
        content.contains("js-taint-sqli-high"),
        "TypeScript should use the same JS taint rules"
    );
}

#[test]
fn test_default_taint_rules_for_go() {
    let runner = SemgrepRunner::new(vec![], vec![]).with_languages(vec!["go".to_string()]);

    let defaults = runner.derive_default_custom_rules();
    assert_eq!(
        defaults.len(),
        1,
        "Go should produce exactly one taint rules file"
    );

    let content = &defaults[0];
    assert!(content.contains("mode: taint"), "should contain taint mode");
    assert!(
        content.contains("go-taint-sqli-high"),
        "should contain Go SQLi rule id"
    );
    assert!(
        content.contains("CWE-22"),
        "should contain CWE-22 (path traversal)"
    );
}

#[test]
fn test_default_taint_rules_for_php() {
    let runner = SemgrepRunner::new(vec![], vec![]).with_languages(vec!["php".to_string()]);

    let defaults = runner.derive_default_custom_rules();
    assert_eq!(
        defaults.len(),
        1,
        "PHP should produce exactly one taint rules file"
    );

    let content = &defaults[0];
    assert!(content.contains("mode: taint"), "should contain taint mode");
    assert!(
        content.contains("php-taint-sqli-high"),
        "should contain PHP SQLi rule id"
    );
    assert!(
        content.contains("php-taint-cmdi-high"),
        "should contain PHP command injection rule id"
    );
    assert!(
        content.contains("php-taint-path-traversal-high"),
        "should contain PHP path traversal rule id"
    );
    assert!(
        content.contains("php-taint-unserialize-high"),
        "should contain PHP unserialize rule id"
    );
}

#[test]
fn test_default_taint_rules_for_c() {
    let runner = SemgrepRunner::new(vec![], vec![]).with_languages(vec!["c".to_string()]);

    let defaults = runner.derive_default_custom_rules();
    assert_eq!(
        defaults.len(),
        1,
        "C should produce exactly one taint rules file"
    );

    let content = &defaults[0];
    assert!(content.contains("mode: taint"), "should contain taint mode");
    assert!(
        content.contains("c-taint-cmdi-high"),
        "should contain C command injection rule id"
    );
    assert!(
        content.contains("c-taint-path-traversal-high"),
        "should contain C path traversal rule id"
    );
}

#[test]
fn test_explicit_custom_rules_do_not_suppress_defaults() {
    // Explicit custom rules should NOT suppress default taint rules.
    // Instead, explicit rules are merged with derived rules, with explicit
    // rules taking precedence on ID collision.
    let runner = SemgrepRunner::new(vec![], vec![])
        .with_languages(vec!["python".to_string()])
        .with_custom_rules(vec!["rules:\n  - id: custom-x\n    languages: [python]\n    mode: taint\n    severity: ERROR\n    message: test\n    pattern-sources: []\n    pattern-sinks: []".to_string()]);

    let defaults = runner.derive_default_custom_rules();
    // Should still get the Python taint rules (not suppressed)
    assert_eq!(
        defaults.len(),
        1,
        "Python taint rules should still be derived even with explicit custom rules"
    );

    let content = &defaults[0];
    assert!(
        content.contains("py-taint-sqli-high"),
        "Should still contain the Python SQLi taint rule"
    );
}

#[test]
fn test_js_and_typescript_dedup() {
    let runner = SemgrepRunner::new(vec![], vec![])
        .with_languages(vec!["javascript".to_string(), "typescript".to_string()]);

    let defaults = runner.derive_default_custom_rules();
    assert_eq!(
        defaults.len(),
        1,
        "JavaScript + TypeScript should produce only one taint rules file (deduplicated)"
    );

    // Verify the content is the JS taint file
    let content = &defaults[0];
    assert!(content.contains("js-taint-sqli-high"));
}

#[test]
fn test_runner_materializes_default_taint_files() {
    let runner = SemgrepRunner::new(vec![], vec![]).with_languages(vec!["python".to_string()]);

    // Materialize effective custom rules (which includes defaults when custom_rules is empty)
    let files = runner
        .materialize_effective_custom_rules()
        .expect("materialize should succeed");

    assert_eq!(
        files.len(),
        1,
        "Should produce one temp file for Python taint rules"
    );

    let path = files[0].path();
    let written = std::fs::read_to_string(path).expect("temp file should be readable");
    assert!(
        written.contains("py-taint-sqli-high"),
        "Materialized file should contain the Python SQLi taint rule"
    );
}

#[test]
fn test_multiple_languages_produce_multiple_rule_sets() {
    let runner = SemgrepRunner::new(vec![], vec![])
        .with_languages(vec!["python".to_string(), "go".to_string()]);

    let defaults = runner.derive_default_custom_rules();
    assert_eq!(
        defaults.len(),
        2,
        "Python + Go should produce two separate taint rules files"
    );

    // Verify both are present
    let combined = defaults.join("\n---\n");
    assert!(combined.contains("py-taint-sqli-high"));
    assert!(combined.contains("go-taint-sqli-high"));
}

#[test]
fn test_default_taint_rules_for_java() {
    let runner = SemgrepRunner::new(vec![], vec![]).with_languages(vec!["java".to_string()]);

    let defaults = runner.derive_default_custom_rules();
    assert_eq!(
        defaults.len(),
        1,
        "Java should produce exactly one taint rules file"
    );

    let content = &defaults[0];
    assert!(content.contains("mode: taint"), "should contain taint mode");
    assert!(
        content.contains("java-taint-sqli-high"),
        "should contain Java SQLi rule id"
    );
    assert!(
        content.contains("java-taint-deserialization-high"),
        "should contain Java deserialization rule id"
    );
}

#[test]
fn test_default_taint_rules_for_ruby() {
    let runner = SemgrepRunner::new(vec![], vec![]).with_languages(vec!["ruby".to_string()]);

    let defaults = runner.derive_default_custom_rules();
    assert_eq!(
        defaults.len(),
        1,
        "Ruby should produce exactly one taint rules file"
    );

    let content = &defaults[0];
    assert!(content.contains("mode: taint"), "should contain taint mode");
    assert!(
        content.contains("ruby-taint-sqli-high"),
        "should contain Ruby SQLi rule id"
    );
    assert!(
        content.contains("ruby-taint-code-injection-high"),
        "should contain Ruby code injection rule id"
    );
}

#[test]
fn test_default_taint_rules_for_csharp() {
    let runner = SemgrepRunner::new(vec![], vec![]).with_languages(vec!["csharp".to_string()]);

    let defaults = runner.derive_default_custom_rules();
    assert_eq!(
        defaults.len(),
        1,
        "C# should produce exactly one taint rules file"
    );

    let content = &defaults[0];
    assert!(content.contains("mode: taint"), "should contain taint mode");
    assert!(
        content.contains("csharp-taint-sqli-high"),
        "should contain C# SQLi rule id"
    );
    assert!(
        content.contains("csharp-taint-deserialization-high"),
        "should contain C# deserialization rule id"
    );
}

#[test]
fn test_cpp_language_alias() {
    let runner = SemgrepRunner::new(vec![], vec![]).with_languages(vec!["cpp".to_string()]);

    let defaults = runner.derive_default_custom_rules();
    assert_eq!(
        defaults.len(),
        1,
        "C++ should produce exactly one taint rules file"
    );

    let content = &defaults[0];
    assert!(
        content.contains("c-taint-cmdi-high"),
        "C++ should use the C taint rules"
    );
}

#[test]
fn test_csharp_aliases() {
    let runner_cs = SemgrepRunner::new(vec![], vec![]).with_languages(vec!["cs".to_string()]);
    let runner_csharp = SemgrepRunner::new(vec![], vec![]).with_languages(vec!["c#".to_string()]);

    let defaults_cs = runner_cs.derive_default_custom_rules();
    let defaults_csharp = runner_csharp.derive_default_custom_rules();

    assert_eq!(defaults_cs.len(), 1, "cs alias should work");
    assert_eq!(defaults_csharp.len(), 1, "c# alias should work");
    assert!(
        defaults_cs[0].contains("csharp-taint-sqli-high"),
        "cs alias should produce C# rules"
    );
    assert!(
        defaults_csharp[0].contains("csharp-taint-sqli-high"),
        "c# alias should produce C# rules"
    );
}
