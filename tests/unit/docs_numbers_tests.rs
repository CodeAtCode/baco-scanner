//! Documentation drift tests — validate that docs match code-derived facts.
//!
//! These tests read markdown files at test time and assert against facts derived from code.
//! They fail CI if documentation becomes stale with respect to the implementation.

/// Count ScanPhase variants from the checkpoint module source.
/// Reads the source file and counts enum variants.
fn count_scan_phases_from_code() -> usize {
    let source = include_str!("../../src/scanner/checkpoint.rs");
    // Find the ScanPhase enum and count its variants
    // Look for the all_phases array which lists all variants explicitly
    let all_phases_start = source.find("let all_phases = [");
    if let Some(start) = all_phases_start {
        let rest = &source[start..];
        let end = rest.find("];").unwrap_or(rest.len());
        let array_content = &rest[..end];
        // Count ScanPhase:: occurrences
        array_content.matches("ScanPhase::").count()
    } else {
        0
    }
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
