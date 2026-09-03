use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub fn load_phase_prompts(base_path: Option<&str>) -> HashMap<String, String> {
    let mut prompts = HashMap::new();
    let base = base_path.unwrap_or("prompts");
    let phases_dir = Path::new(base).join("phases");

    let phase_files = [
        ("indexing", "indexing.md"),
        ("semgrep", "semgrep.md"),
        ("llm_static_analysis", "llm_static_analysis.md"),
        ("llm_discovery", "llm_discovery.md"),
        ("llm_verification", "llm_verification.md"),
        ("ticket_crossref", "ticket_crossref.md"),
        ("git_analysis", "git_analysis.md"),
        ("cross_file_analysis", "cross_file_analysis.md"),
        ("confidence_scoring", "confidence_scoring.md"),
        ("ai_aggregation", "ai_aggregation.md"),
        ("reporting", "reporting.md"),
    ];

    for (phase_name, filename) in phase_files {
        let filepath = phases_dir.join(filename);
        let clean_content = fs::read_to_string(&filepath)
            .map(|content| content.trim().to_string())
            .unwrap_or_else(|_| {
                tracing::warn!("Warning: Could not load prompt file: {:?}", filepath);
                String::new()
            });
        prompts.insert(phase_name.to_string(), clean_content);
    }

    prompts
}

/// Load hunt domain prompts from prompts/hunt/*.md files
pub fn load_hunt_prompts(base_path: Option<&str>) -> HashMap<String, String> {
    let mut prompts = HashMap::new();
    let base = base_path.unwrap_or("prompts");
    let hunt_dir = Path::new(base).join("hunt");

    let hunt_domains = [
        ("injection", "injection.md"),
        ("auth", "auth.md"),
        ("xss", "xss.md"),
        ("path_traversal", "path_traversal.md"),
        ("crypto", "crypto.md"),
        ("resource", "resource.md"),
        ("deserialization", "deserialization.md"),
    ];

    for (domain_name, filename) in hunt_domains {
        let filepath = hunt_dir.join(filename);
        let clean_content = fs::read_to_string(&filepath)
            .map(|content| content.trim().to_string())
            .unwrap_or_else(|_| {
                tracing::warn!("Warning: Could not load hunt prompt file: {:?}", filepath);
                String::new()
            });
        prompts.insert(domain_name.to_string(), clean_content);
    }

    prompts
}

pub fn get_prompt(
    phase_name: &str,
    loaded_prompts: &HashMap<String, String>,
    config_override: Option<&str>,
    default_prompt: &str,
) -> String {
    config_override
        .map(String::from)
        .or_else(|| {
            loaded_prompts
                .get(phase_name)
                .filter(|s| !s.is_empty())
                .cloned()
        })
        .unwrap_or_else(|| default_prompt.to_string())
}
