//! Documentation coverage: every config.example.toml section must be documented
//! in docs/configuration.md, and every user-facing CLI subcommand must appear
//! in README.md. Keeps docs honest as new sections/subcommands are added.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn every_example_config_section_is_documented() {
    let example =
        fs::read_to_string(repo_root().join("config.example.toml")).expect("example readable");
    let docs = fs::read_to_string(repo_root().join("docs/configuration.md"))
        .expect("configuration.md readable");

    let mut sections: Vec<String> = example
        .lines()
        .filter_map(|l| {
            let t = l.trim();
            if t.starts_with('#') {
                return None;
            }
            // Handles both [section] and [[array-of-tables]] headers
            let inner = t.trim_start_matches('[').trim_end_matches(']');
            if inner.contains(' ') || inner.is_empty() {
                return None;
            }
            Some(inner.to_string())
        })
        .collect();
    sections.sort();
    sections.dedup();

    assert!(
        !sections.is_empty(),
        "no sections extracted — the TOML parser in this test is broken"
    );

    let mut missing = Vec::new();
    for section in &sections {
        // Dotted sections like [llm.phases.discovery] are documented under
        // their root ([llm] + the LLM phases docs); check the root name.
        let root = section.split('.').next().unwrap_or(section);
        let documented = docs.contains(&format!("[{}]", root))
            || docs.contains(&format!("[[{}]]", root))
            || docs.contains(&format!("`{}`", root));
        if !documented {
            missing.push(section.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "config.example.toml sections missing from docs/configuration.md: {:?}",
        missing
    );
}

#[test]
fn every_cli_subcommand_is_in_readme() {
    let readme = fs::read_to_string(repo_root().join("README.md")).expect("README readable");
    // Keep in sync with the Commands enum in src/main.rs when adding a
    // user-facing subcommand (internal listing helpers excluded).
    let subcommands = [
        "scan", "report", "verify", "resume", "preset", "doctor", "eval", "init",
    ];
    let missing: Vec<&str> = subcommands
        .iter()
        .filter(|c| !readme.contains(&format!("baco {}", c)))
        .copied()
        .collect();
    assert!(
        missing.is_empty(),
        "CLI subcommands missing from README.md: {:?}",
        missing
    );
}

#[test]
fn example_config_parses_and_eval_floor_is_valid() {
    // Guards the newest section: [eval] must parse into the config and its
    // floor must sit inside the valid range.
    let raw =
        fs::read_to_string(repo_root().join("config.example.toml")).expect("example readable");
    let config: baco::config::ScannerConfig =
        toml::from_str(&raw).expect("config.example.toml must deserialize");
    assert!(
        (0.0..=1.0).contains(&config.eval.floor),
        "example [eval] floor out of range: {}",
        config.eval.floor
    );
}
