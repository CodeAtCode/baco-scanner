//! Documentation drift tests — validate that docs match code-derived facts.
//!
//! These tests read markdown files at test time and assert against facts derived from code.
//! They fail CI if documentation becomes stale with respect to the implementation.

/// Count ScanPhase variants from the single-source pipeline table.
fn count_scan_phases_from_code() -> usize {
    baco::scanner::phase_spec::PhaseSpec::total()
}

/// Extract LLM_*_KEY environment variable names from env.rs source.
fn extract_llm_env_vars_from_code() -> Vec<String> {
    let source = include_str!("../../src/config/env.rs");
    let mut vars = Vec::new();

    // Pattern: env::var("LLM_..._KEY")
    for line in source.lines() {
        if let Some(start) = line.find("env::var(\"LLM_") {
            let rest = &line[start + 12..]; // skip "env::var(\"LLM_"
            if let Some(end) = rest.find('"') {
                let var_name = &rest[..end];
                if var_name.ends_with("_KEY") {
                    vars.push(var_name.to_string());
                }
            }
        }
    }

    vars
}

/// Get builtin preset names from preset.rs source.
fn get_builtin_presets_from_code() -> Vec<String> {
    let source = include_str!("../../src/preset.rs");
    let mut presets = Vec::new();

    // Find the BUILTIN_PRESETS array specifically
    let array_start = match source.find("pub const BUILTIN_PRESETS: &[&str] = &[") {
        Some(pos) => pos,
        None => return presets,
    };

    let after_start = &source[array_start..];
    let array_end = match after_start.find("];\n") {
        Some(pos) => pos,
        None => return presets,
    };

    let array_content = &after_start[..array_end];

    // Extract string literals from the array content
    for line in array_content.lines() {
        let trimmed = line.trim();
        // Match lines like: "preset-name",
        if trimmed.starts_with('"') && trimmed.ends_with("\",") {
            let preset_name = &trimmed[1..trimmed.len() - 2];
            if !preset_name.is_empty() {
                presets.push(preset_name.to_string());
            }
        }
    }

    presets
}

#[test]
fn test_phase_count_matches_readme() {
    let phase_count = count_scan_phases_from_code();

    let readme = include_str!("../../README.md");

    // Search for patterns like "24-phase", "24 phases", "24-phase pipeline"
    let re = regex::Regex::new(r"\b(\d+)[-\s]phases?\b").unwrap();

    let mut found_counts: Vec<u32> = Vec::new();
    for cap in re.captures_iter(readme) {
        if let Ok(count) = cap[1].parse::<u32>() {
            found_counts.push(count);
        }
    }

    // If we found phase count mentions in README, they should match the code
    if !found_counts.is_empty() {
        for found in &found_counts {
            assert_eq!(
                *found as usize, phase_count,
                "README mentions {} phases but code has {} phases (from src/scanner/checkpoint.rs)",
                found, phase_count
            );
        }
    }
}

#[test]
fn test_phase_count_matches_architecture_docs() {
    let phase_count = count_scan_phases_from_code();

    let arch = include_str!("../../docs/architecture.md");

    // Search for patterns like "24 phases", "24-phase"
    let re = regex::Regex::new(r"\b(\d+)[-\s]phases?\b").unwrap();

    let mut found_counts: Vec<u32> = Vec::new();
    for cap in re.captures_iter(arch) {
        if let Ok(count) = cap[1].parse::<u32>() {
            found_counts.push(count);
        }
    }

    // If we found phase count mentions in architecture docs, they should match the code
    if !found_counts.is_empty() {
        for found in &found_counts {
            assert_eq!(
                *found as usize,
                phase_count,
                "Architecture docs mention {} phases but code has {} phases (from src/scanner/checkpoint.rs)",
                found,
                phase_count
            );
        }
    }
}

#[test]
fn test_builtin_presets_documented() {
    let builtin_presets = get_builtin_presets_from_code();
    let config_docs = include_str!("../../docs/configuration.md");

    for preset in &builtin_presets {
        assert!(
            config_docs.contains(preset),
            "Builtin preset '{}' from src/preset.rs is not documented in docs/configuration.md",
            preset
        );
    }
}

#[test]
fn test_no_undocumented_presets_in_docs() {
    let builtin_presets = get_builtin_presets_from_code();
    let config_docs = include_str!("../../docs/configuration.md");

    // Extract preset names mentioned in docs (from the presets table)
    let mut doc_presets: Vec<String> = Vec::new();
    for line in config_docs.lines() {
        if line.trim().starts_with('|') && line.contains('|') {
            let parts: Vec<&str> = line.split('|').collect();
            for part in parts {
                let trimmed = part.trim();
                // Look for preset-like names (no spaces, alphanumeric + dash/underscore)
                if trimmed
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                    && !trimmed.is_empty()
                    && trimmed.len() < 30
                {
                    // Check if it looks like a preset name
                    if trimmed.contains("wordpress")
                        || trimmed.contains("django")
                        || trimmed.contains("laravel")
                        || trimmed == "cpp"
                        || trimmed == "litellm"
                        || trimmed == "oss-python"
                        || trimmed == "oss-monorepo"
                    {
                        doc_presets.push(trimmed.to_string());
                    }
                }
            }
        }
    }

    // Check that all doc presets are in builtin list
    for doc_preset in &doc_presets {
        assert!(
            builtin_presets.contains(doc_preset),
            "Preset '{}' mentioned in docs/configuration.md is not a builtin preset (src/preset.rs)",
            doc_preset
        );
    }
}

#[test]
fn test_llm_env_vars_documented() {
    let llm_env_vars = extract_llm_env_vars_from_code();
    let config_docs = include_str!("../../docs/configuration.md");

    for env_var in &llm_env_vars {
        assert!(
            config_docs.contains(env_var),
            "Environment variable '{}' from src/config/env.rs is not documented in docs/configuration.md",
            env_var
        );
    }
}

#[test]
fn test_env_var_count_matches_docs() {
    let llm_env_vars = extract_llm_env_vars_from_code();
    let config_docs = include_str!("../../docs/configuration.md");

    // Count LLM_*_KEY entries in docs table
    let mut doc_llm_key_count = 0;
    for line in config_docs.lines() {
        if line.contains("LLM_") && line.contains("_KEY") {
            doc_llm_key_count += 1;
        }
    }

    assert_eq!(
        doc_llm_key_count,
        llm_env_vars.len(),
        "docs/configuration.md documents {} LLM_*_KEY env vars but src/config/env.rs reads {} (missing: {:?})",
        doc_llm_key_count,
        llm_env_vars.len(),
        llm_env_vars
    );
}

/// Count integrated papers from research-integration.md table
fn count_papers_from_research_integration() -> usize {
    let content = include_str!("../../docs/research-integration.md");

    // Count table rows in the Integration Status Summary table
    // Pattern: | Paper Name | ... | Status |
    let mut count = 0;
    for line in content.lines() {
        if line.trim().starts_with('|')
            && line.contains('|')
            && !line.contains("| Paper |")  // skip header
            && !line.contains("|-------|")
        // skip separator
        {
            count += 1;
        }
    }
    count
}

#[test]
fn test_papers_count_matches_research_integration() {
    let papers_count = count_papers_from_research_integration();

    let readme = include_str!("../../README.md");
    let docs_readme = include_str!("../../docs/README.md");
    let research_doc = include_str!("../../docs/research-integration.md");
    let contributing = include_str!("../../CONTRIBUTING.md");

    // All docs should cite the same papers count
    let re = regex::Regex::new(r"(\d+)\s*papers?").unwrap();

    // Check README and docs/README.md. Lines mentioning the SURVEY are skipped:
    // the survey cites 36 SURVEYED papers — a different, true number. Only the
    // integrated count must match research-integration.md.
    for (label, text) in [("README.md", readme), ("docs/README.md", docs_readme)] {
        for line in text.lines() {
            if line.to_lowercase().contains("survey") {
                continue;
            }
            for cap in re.captures_iter(line) {
                let count: usize = cap[1].parse().unwrap();
                if count > 10 {
                    assert_eq!(
                        count, papers_count,
                        "{} cites {} papers but docs/research-integration.md has {} entries",
                        label, count, papers_count
                    );
                }
            }
        }
    }

    // Check research-integration.md itself
    for line in research_doc.lines() {
        if line.to_lowercase().contains("survey") {
            continue;
        }
        for cap in re.captures_iter(line) {
            let count: usize = cap[1].parse().unwrap();
            if count > 10 {
                assert_eq!(
                    count, papers_count,
                    "docs/research-integration.md cites {} papers but has {} entries",
                    count, papers_count
                );
            }
        }
    }

    // Check CONTRIBUTING.md if it exists and mentions papers
    if contributing.contains("paper") || contributing.contains("Paper") {
        for cap in re.captures_iter(contributing) {
            let count: usize = cap[1].parse().unwrap();
            if count > 10 {
                assert_eq!(
                    count, papers_count,
                    "CONTRIBUTING.md cites {} papers but docs/research-integration.md has {} entries",
                    count, papers_count
                );
            }
        }
    }
}
