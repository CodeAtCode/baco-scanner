use std::fs;
use std::path::Path;

const PROMPTS_HUNT_DIR: &str = "prompts/hunt";
const PROMPTS_PHASES_DIR: &str = "prompts/phases";

fn read_file_content(relative_path: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let full_path = Path::new(manifest_dir).join(relative_path);
    fs::read_to_string(&full_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", full_path.display(), e))
}

#[test]
fn test_all_hunt_modules_have_scope_section() {
    let hunt_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(PROMPTS_HUNT_DIR);
    assert!(hunt_dir.exists(), "Hunt directory must exist");

    let md_files: Vec<_> = fs::read_dir(&hunt_dir)
        .expect("Cannot read hunt directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "md"))
        .collect();

    assert!(!md_files.is_empty(), "No .md files found in prompts/hunt");

    for md_file in md_files {
        let content =
            fs::read_to_string(&md_file).unwrap_or_else(|_| panic!("Cannot read {:?}", md_file));

        assert!(
            content.contains("## Scope — stay in your lane"),
            "Missing '## Scope — stay in your lane' section in {:?}",
            md_file
        );
    }
}

#[test]
fn test_llm_verification_has_skeptical_gate_and_untrusted_content() {
    let content = read_file_content(&format!("{}/llm_verification.md", PROMPTS_PHASES_DIR));

    assert!(
        content.contains("## Skeptical gate — before you emit"),
        "llm_verification.md missing '## Skeptical gate — before you emit' section"
    );

    assert!(
        content.contains("## Untrusted content"),
        "llm_verification.md missing '## Untrusted content' section"
    );
}

#[test]
fn test_llm_static_analysis_has_untrusted_content() {
    let content = read_file_content(&format!("{}/llm_static_analysis.md", PROMPTS_PHASES_DIR));

    assert!(
        content.contains("## Untrusted content"),
        "llm_static_analysis.md missing '## Untrusted content' section"
    );
}

#[test]
fn test_llm_discovery_has_untrusted_content() {
    let content = read_file_content(&format!("{}/llm_discovery.md", PROMPTS_PHASES_DIR));

    assert!(
        content.contains("## Untrusted content"),
        "llm_discovery.md missing '## Untrusted content' section"
    );
}

#[test]
fn test_authz_absence_has_ground_model_and_sibling_branch() {
    let content = read_file_content(&format!("{}/authz_absence.md", PROMPTS_HUNT_DIR));

    assert!(
        content.contains("ground model"),
        "authz_absence.md must mention 'ground model' concept"
    );

    assert!(
        content.contains("sibling"),
        "authz_absence.md must mention 'sibling branch' concept for false positive prevention"
    );
}

#[test]
fn test_scope_sections_declare_owned_class() {
    let hunt_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(PROMPTS_HUNT_DIR);

    let md_files: Vec<_> = fs::read_dir(&hunt_dir)
        .expect("Cannot read hunt directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "md"))
        .collect();

    for md_file in md_files {
        let content =
            fs::read_to_string(&md_file).unwrap_or_else(|_| panic!("Cannot read {:?}", md_file));

        let scope_start = content
            .find("## Scope — stay in your lane")
            .unwrap_or_else(|| panic!("No scope section in {:?}", md_file));

        let scope_section = &content[scope_start..];

        assert!(
            scope_section.contains("OWNED CLASS:") || scope_section.contains("OWNED"),
            "Scope section in {:?} must declare owned class",
            md_file
        );
    }
}
