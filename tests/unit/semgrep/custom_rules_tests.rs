//! Regression tests for preset-shipped inline semgrep rules (`custom_rules`).
//!
//! The WordPress presets embed semgrep rule YAML directly in the TOML so they
//! stay self-contained. These tests guard the shipped rule set and the runner's
//! materialization path (inline YAML -> temp .yml file for `semgrep --config`).

use baco::config::ScannerConfig;
use baco::preset::load_preset;
use baco::semgrep::SemgrepRunner;

const EXPECTED_RULE_IDS: [&str; 4] = [
    "wp-superglobal-file-read-high",
    "wp-open-redirect-superglobal-medium",
    "wp-ajax-dispatch-missing-nonce-high",
    "php-weak-hash-md5-medium",
];

#[test]
fn wordpress_presets_ship_custom_rules() {
    for name in ["wordpress-core", "wordpress-plugin"] {
        let overlay = load_preset(name).expect("preset should load");
        let mut config = ScannerConfig::default();
        overlay.merge_into(&mut config);

        assert!(
            !config.scanner.semgrep.custom_rules.is_empty(),
            "{name} should ship custom_rules through the preset merge"
        );

        let merged = config.scanner.semgrep.custom_rules.join("\n");
        for id in EXPECTED_RULE_IDS {
            assert!(
                merged.contains(id),
                "{name} custom_rules missing rule id '{id}'"
            );
        }
    }
}

#[test]
fn custom_rules_merge_replaces_base() {
    let overlay = load_preset("wordpress-plugin").expect("preset should load");
    let mut config = ScannerConfig::default();
    config.scanner.semgrep.custom_rules = vec!["rules: []".to_string()];
    overlay.merge_into(&mut config);

    assert!(
        !config
            .scanner
            .semgrep
            .custom_rules
            .contains(&"rules: []".to_string()),
        "preset custom_rules should override the base value, not append to it"
    );
}

#[test]
fn materialize_custom_rules_writes_temp_yml() {
    let yaml = "rules:\n  - id: test-rule-abc\n    languages: [php]\n";
    let runner = SemgrepRunner::new(vec![], vec![]).with_custom_rules(vec![yaml.to_string()]);

    let files = runner.materialize_custom_rules().expect("materialize ok");
    assert_eq!(files.len(), 1);

    let path = files[0].path();
    let file_name = path.file_name().unwrap().to_string_lossy();
    assert!(
        file_name.ends_with(".yml"),
        "temp file must keep the .yml suffix so semgrep treats it as YAML config: {file_name}"
    );

    let written = std::fs::read_to_string(path).expect("temp file readable");
    assert_eq!(
        written, yaml,
        "materialized content must match the inline YAML"
    );
}

#[test]
fn materialize_custom_rules_empty_is_noop() {
    let runner = SemgrepRunner::new(vec![], vec![]);
    let files = runner.materialize_custom_rules().expect("materialize ok");
    assert!(
        files.is_empty(),
        "no custom rules should produce no temp files"
    );
}
