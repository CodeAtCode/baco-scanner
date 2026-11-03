//! Tests for taint rule YAML files: parsing, structure, and uniqueness.
//!
//! Verifies that all bundled taint rule files:
//! - Parse as valid YAML
//! - Have `mode: taint` on each rule
//! - Have at least two rules per file
//! - Have globally unique rule IDs across all files

use std::collections::BTreeSet;

const TAINT_PHP_RULES: &str = include_str!("../../../src/semgrep/rules/taint-php.yml");
const TAINT_C_RULES: &str = include_str!("../../../src/semgrep/rules/taint-c.yml");
const TAINT_JAVA_RULES: &str = include_str!("../../../src/semgrep/rules/taint-java.yml");
const TAINT_RUBY_RULES: &str = include_str!("../../../src/semgrep/rules/taint-ruby.yml");
const TAINT_CSHARP_RULES: &str = include_str!("../../../src/semgrep/rules/taint-csharp.yml");

#[derive(Debug)]
struct RuleInfo {
    id: String,
    mode: String,
    file: &'static str,
}

fn parse_rules_from_yaml(yaml: &str, file: &'static str) -> Result<Vec<RuleInfo>, String> {
    #[derive(serde::Deserialize)]
    struct Rule {
        id: String,
        mode: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct RulesDoc {
        rules: Vec<Rule>,
    }

    let parsed: RulesDoc = serde_yaml::from_str(yaml)
        .map_err(|e| format!("Failed to parse {} as YAML: {}", file, e))?;

    let mut rules = Vec::new();
    for rule in parsed.rules {
        let mode = rule.mode.unwrap_or_else(|| "unknown".to_string());
        rules.push(RuleInfo {
            id: rule.id,
            mode,
            file,
        });
    }

    Ok(rules)
}

#[test]
fn test_php_taint_yaml_parses() {
    let rules = parse_rules_from_yaml(TAINT_PHP_RULES, "taint-php.yml")
        .expect("PHP taint YAML should parse");

    assert!(
        !rules.is_empty(),
        "PHP taint file should have at least one rule"
    );
    assert!(
        rules.len() >= 2,
        "PHP taint file should have at least two rules, found {}",
        rules.len()
    );
}

#[test]
fn test_php_taint_rules_have_taint_mode() {
    let rules = parse_rules_from_yaml(TAINT_PHP_RULES, "taint-php.yml")
        .expect("PHP taint YAML should parse");

    for rule in &rules {
        assert_eq!(
            rule.mode, "taint",
            "Rule {} in {} should have mode: taint, got '{}'",
            rule.id, rule.file, rule.mode
        );
    }
}

#[test]
fn test_c_taint_yaml_parses() {
    let rules =
        parse_rules_from_yaml(TAINT_C_RULES, "taint-c.yml").expect("C taint YAML should parse");

    assert!(
        rules.len() >= 2,
        "C taint file should have at least two rules, found {}",
        rules.len()
    );
}

#[test]
fn test_c_taint_rules_have_taint_mode() {
    let rules =
        parse_rules_from_yaml(TAINT_C_RULES, "taint-c.yml").expect("C taint YAML should parse");

    for rule in &rules {
        assert_eq!(
            rule.mode, "taint",
            "Rule {} in {} should have mode: taint, got '{}'",
            rule.id, rule.file, rule.mode
        );
    }
}

#[test]
fn test_java_taint_yaml_parses() {
    let rules = parse_rules_from_yaml(TAINT_JAVA_RULES, "taint-java.yml")
        .expect("Java taint YAML should parse");

    assert!(
        rules.len() >= 2,
        "Java taint file should have at least two rules, found {}",
        rules.len()
    );
}

#[test]
fn test_java_taint_rules_have_taint_mode() {
    let rules = parse_rules_from_yaml(TAINT_JAVA_RULES, "taint-java.yml")
        .expect("Java taint YAML should parse");

    for rule in &rules {
        assert_eq!(
            rule.mode, "taint",
            "Rule {} in {} should have mode: taint, got '{}'",
            rule.id, rule.file, rule.mode
        );
    }
}

#[test]
fn test_ruby_taint_yaml_parses() {
    let rules = parse_rules_from_yaml(TAINT_RUBY_RULES, "taint-ruby.yml")
        .expect("Ruby taint YAML should parse");

    assert!(
        rules.len() >= 2,
        "Ruby taint file should have at least two rules, found {}",
        rules.len()
    );
}

#[test]
fn test_ruby_taint_rules_have_taint_mode() {
    let rules = parse_rules_from_yaml(TAINT_RUBY_RULES, "taint-ruby.yml")
        .expect("Ruby taint YAML should parse");

    for rule in &rules {
        assert_eq!(
            rule.mode, "taint",
            "Rule {} in {} should have mode: taint, got '{}'",
            rule.id, rule.file, rule.mode
        );
    }
}

#[test]
fn test_csharp_taint_yaml_parses() {
    let rules = parse_rules_from_yaml(TAINT_CSHARP_RULES, "taint-csharp.yml")
        .expect("C# taint YAML should parse");

    assert!(
        rules.len() >= 2,
        "C# taint file should have at least two rules, found {}",
        rules.len()
    );
}

#[test]
fn test_csharp_taint_rules_have_taint_mode() {
    let rules = parse_rules_from_yaml(TAINT_CSHARP_RULES, "taint-csharp.yml")
        .expect("C# taint YAML should parse");

    for rule in &rules {
        assert_eq!(
            rule.mode, "taint",
            "Rule {} in {} should have mode: taint, got '{}'",
            rule.id, rule.file, rule.mode
        );
    }
}

#[test]
fn test_all_taint_rule_ids_are_unique() {
    let all_yaml = vec![
        (TAINT_PHP_RULES, "taint-php.yml"),
        (TAINT_C_RULES, "taint-c.yml"),
        (TAINT_JAVA_RULES, "taint-java.yml"),
        (TAINT_RUBY_RULES, "taint-ruby.yml"),
        (TAINT_CSHARP_RULES, "taint-csharp.yml"),
    ];

    let mut all_ids = BTreeSet::new();
    let mut duplicates = Vec::new();

    for (yaml, file) in all_yaml {
        let rules = parse_rules_from_yaml(yaml, file).expect("YAML should parse");
        for rule in rules {
            if !all_ids.insert(rule.id.clone()) {
                duplicates.push(rule.id);
            }
        }
    }

    assert!(
        duplicates.is_empty(),
        "Found duplicate rule IDs across all taint files: {:?}",
        duplicates
    );
}

#[test]
fn test_total_rule_count() {
    let all_yaml = vec![
        (TAINT_PHP_RULES, "taint-php.yml", 4),
        (TAINT_C_RULES, "taint-c.yml", 2),
        (TAINT_JAVA_RULES, "taint-java.yml", 4),
        (TAINT_RUBY_RULES, "taint-ruby.yml", 4),
        (TAINT_CSHARP_RULES, "taint-csharp.yml", 4),
    ];

    let mut total = 0;
    for (yaml, file, expected_min) in all_yaml {
        let rules = parse_rules_from_yaml(yaml, file).expect("YAML should parse");
        total += rules.len();
        assert!(
            rules.len() >= expected_min,
            "{} should have at least {} rules, found {}",
            file,
            expected_min,
            rules.len()
        );
    }

    assert_eq!(
        total, 18,
        "Total rule count across all 5 new taint files should be 18"
    );
}
