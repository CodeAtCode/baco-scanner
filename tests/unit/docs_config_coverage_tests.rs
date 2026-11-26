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

/// Every "N-phase" claim in the user-facing docs must match the pipeline.
///
/// The count drifted once already: after the experimental tier was removed, four
/// places still advertised a 23-phase pipeline. A prose number cannot be
/// generated, so it is checked instead.
#[test]
fn documented_phase_count_matches_the_pipeline() {
    let root = repo_root();
    let total = baco::scanner::phase_spec::PhaseSpec::total();

    let mut files = vec![root.join("README.md")];
    let docs = root.join("docs");
    for entry in fs::read_dir(&docs).expect("docs directory must exist") {
        let path = entry.expect("readable docs entry").path();
        if path.extension().is_some_and(|e| e == "md") {
            files.push(path);
        }
    }
    // Source comments carry the same claim: "phase 14 of 23" survived there.
    collect_rust_sources(&root.join("src"), &mut files);

    let mut claims = 0;
    for path in &files {
        let text = fs::read_to_string(path).expect("docs file is readable");
        for (line_no, line) in text.lines().enumerate() {
            for claim in phase_count_claims(line) {
                claims += 1;
                assert_eq!(
                    claim,
                    total,
                    "{}:{} states a {}-phase pipeline, but PhaseSpec::total() is {}",
                    path.display(),
                    line_no + 1,
                    claim,
                    total
                );
            }
        }
    }

    // The walk must actually have found the claims, or this test proves nothing.
    assert!(
        claims >= 3,
        "expected at least 3 phase-count claims in the docs, found {claims}"
    );
}

/// The phase counts a line claims, from `<n>-phase` and `<n> phases`.
fn phase_count_claims(line: &str) -> Vec<usize> {
    let mut found = Vec::new();

    for marker in ["-phase", " phases"] {
        for (idx, _) in line.match_indices(marker) {
            let digits: String = line[..idx]
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_digit())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if let Ok(n) = digits.parse::<usize>() {
                found.push(n);
            }
        }
    }

    // "phase 14 of 23" — the number after `of` is the total.
    if line.to_lowercase().contains("phase") {
        for (idx, _) in line.match_indices(" of ") {
            let digits: String = line[idx + 4..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(n) = digits.parse::<usize>() {
                found.push(n);
            }
        }
    }

    found
}

/// Collect every `.rs` file under `dir`, recursively.
fn collect_rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Removed phases and removed config keys must not still be advertised.
///
/// The README described "optional phases" adding rule synthesis, exploit
/// synthesis, threat modeling, auto-patching and PoC compilation long after those
/// phases were deleted from the pipeline, and the docs still promised config keys
/// that no longer exist.
#[test]
fn removed_phases_are_not_advertised_in_the_docs() {
    let root = repo_root();
    let mut docs = Vec::new();
    for entry in fs::read_dir(root.join("docs")).expect("docs directory must exist") {
        let path = entry.expect("readable docs entry").path();
        if path.extension().is_some_and(|e| e == "md") {
            docs.push(path);
        }
    }
    let readme = root.join("README.md");

    // Naming a technique in the research survey is fine; advertising it as a
    // phase of the pipeline is not.
    let removed_config_keys = [
        "rulesynth.enabled",
        "cpg.enabled",
        "exploit.enabled",
        "variant_search",
        "profile = \"core\"",
    ];
    let removed_subsystems = ["joern", "cpg-guided", "cpg-based", "code property graph"];
    let removed_phases = [
        "rule synthesis",
        "exploit synthesis",
        "threat modeling",
        "auto-patching",
        "poc compilation",
    ];

    let mut targets = docs.clone();
    targets.push(readme.clone());
    for path in &targets {
        let text = fs::read_to_string(path)
            .expect("docs file is readable")
            .to_lowercase();
        for key in removed_config_keys {
            assert!(
                !text.contains(key),
                "{} still promises the removed config key `{}`",
                path.display(),
                key
            );
        }
    }

    // The research surveys describe papers and their techniques; naming a
    // subsystem there is context, not a claim that BACO ships it.
    let mut operational = vec![readme];
    operational.extend(docs.into_iter().filter(|p| {
        !p.ends_with("research-integration.md")
            && !p.ends_with("llm-vuln-detection-papers-survey.md")
    }));
    for path in &operational {
        let text = fs::read_to_string(path)
            .expect("docs file is readable")
            .to_lowercase();
        for phrase in removed_subsystems {
            assert!(
                !text.contains(phrase),
                "{} still describes the removed CPG/Joern subsystem (`{}`)",
                path.display(),
                phrase
            );
        }
        for phrase in removed_phases {
            assert!(
                !text.contains(phrase),
                "{} still advertises the removed phase `{}`",
                path.display(),
                phrase
            );
        }
    }
}
