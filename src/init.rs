/// `baco init` subcommand - Quickstart configuration generator
///
/// Generates a minimal baco.toml config file for a target project directory.
use crate::error::ScanError;
use clap::Args;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Initialize a new baco configuration
#[derive(Args, Debug)]
pub struct InitCommand {
    /// Target directory to scan (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Overwrite existing baco.toml if it exists
    #[arg(long, default_value = "false")]
    pub force: bool,
}

/// Language detection based on file extensions
pub fn detect_languages_in_dir(dir: &Path) -> HashSet<String> {
    let mut languages = HashSet::new();

    let extensions = [
        ("py", "python"),
        ("js", "javascript"),
        ("ts", "typescript"),
        ("tsx", "typescript"),
        ("rs", "rust"),
        ("go", "go"),
        ("java", "java"),
        ("c", "c"),
        ("cpp", "cpp"),
        ("cc", "cpp"),
        ("cxx", "cpp"),
        ("h", "cpp"),
        ("hpp", "cpp"),
        ("php", "php"),
        ("sql", "sql"),
        ("yml", "yaml"),
        ("yaml", "yaml"),
        ("json", "json"),
        ("sh", "bash"),
        ("bash", "bash"),
        ("rb", "ruby"),
        ("kt", "kotlin"),
        ("scala", "scala"),
        ("pl", "perl"),
        ("pm", "perl"),
        ("lua", "lua"),
        ("sol", "solidity"),
        ("cs", "csharp"),
        ("swift", "swift"),
    ];

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if let Some(&(_, lang)) = extensions
                        .iter()
                        .find(|(ext_lang, _)| ext.eq_ignore_ascii_case(ext_lang))
                    {
                        languages.insert(lang.to_string());
                    }
                }
            }
        }
    }

    languages
}

/// Detect project markers for preset suggestion
pub fn detect_project_markers(dir: &Path) -> Vec<String> {
    let mut markers = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let filename = entry.file_name().to_string_lossy().to_lowercase();
            let path_str = entry.path().to_string_lossy().to_lowercase();
            match filename.as_str() {
                "wp-content" | "wp-includes" | "wp-config.php" => {
                    markers.push("wordpress".to_string());
                }
                "manage.py" | "requirements-django.txt" => {
                    markers.push("django".to_string());
                }
                "artisan" => {
                    markers.push("laravel".to_string());
                }
                _ => {
                    // Check for path-based markers (e.g., config/app.php)
                    if path_str.contains("/config/app.php") {
                        markers.push("laravel".to_string());
                    }
                }
            }
        }
    }

    markers
}

/// Suggest a preset based on detected languages and markers
pub fn suggest_preset(languages: &HashSet<String>, markers: &[String]) -> Option<String> {
    // Check markers first
    if markers.contains(&"wordpress".to_string()) && languages.contains(&"php".to_string()) {
        return Some("wordpress-plugin".to_string());
    }
    if markers.contains(&"django".to_string()) && languages.contains(&"python".to_string()) {
        return Some("django".to_string());
    }
    if markers.contains(&"laravel".to_string()) && languages.contains(&"php".to_string()) {
        return Some("laravel".to_string());
    }

    // Laravel without explicit PHP marker (artisan file is PHP)
    if markers.contains(&"laravel".to_string()) {
        return Some("laravel".to_string());
    }

    // Fall back to language-based suggestions
    if languages.contains(&"cpp".to_string()) || languages.contains(&"c".to_string()) {
        return Some("cpp".to_string());
    }

    None
}

/// Generate baco.toml content
pub fn generate_config_content(
    project_name: &str,
    project_path: &str,
    languages: &[String],
    suggested_preset: Option<&str>,
) -> String {
    let languages_str = languages
        .iter()
        .map(|l| format!("\"{}\"", l))
        .collect::<Vec<_>>()
        .join(", ");

    let preset_comment = if let Some(preset) = suggested_preset {
        format!(
            "\n# Suggested preset: {}\n# To use it, run: baco scan --preset {}\n",
            preset, preset
        )
    } else {
        "\n# No preset suggested for this project type\n".to_string()
    };

    format!(
        r#"[project]
# Project name (shown in reports)
name = "{}"

# Path to the project directory (relative to this config file or absolute)
path = "{}"

# Detected languages - edit to add/remove as needed
languages = [{}]

[output]
# Output directory for findings and reports
dir = "baco-output"

# Enable evidence gate: only independently reproduced findings reach reports
evidence_gate = false

[scanner]
# Scan profile: "core" (default, essential phases) or "all" (all phases)
profile = "core"
# To enable all phases: profile = "all"

# Maximum file size to analyze (in KB)
max_file_size_kb = 512

# Paths to exclude from scanning (glob patterns)
exclude_paths = []

[llm]
# Global LLM timeout (seconds)
timeout_secs = 60

# Maximum concurrent LLM requests
max_concurrent = 4

# LLM temperature for generation
temperature = 0.5

# LLM phases configuration
[llm.phases.discovery]
# base_url = "https://api.mistral.ai/v1"
# api_key = "${{MISTRAL_API_KEY}}"  # or set MISTRAL_API_KEY env var
# models = ["mistral-small"]

[llm.phases.verification]
# base_url = "https://api.mistral.ai/v1"
# api_key = "${{MISTRAL_API_KEY}}"
# models = ["mistral-small"]

[llm.phases.aggregation]
# base_url = "https://api.mistral.ai/v1"
# api_key = "${{MISTRAL_API_KEY}}"
# models = ["mistral-small"]

[llm.phases.static_analysis]
# base_url = "https://api.mistral.ai/v1"
# api_key = "${{MISTRAL_API_KEY}}"
# models = ["mistral-small"]

[llm.phases.security_agent_verification]
# base_url = "https://api.mistral.ai/v1"
# api_key = "${{MISTRAL_API_KEY}}"
# models = ["mistral-small"]

[llm.phases.threat_modeling]
# base_url = "https://api.mistral.ai/v1"
# api_key = "${{MISTRAL_API_KEY}}"
# models = ["mistral-small"]

# Budget configuration to limit LLM costs
[budget]
# Enable budget limits
enabled = false
# Maximum LLM calls per scan
max_llm_calls = 200
# Reserve percentage for high-risk files
reserve_percent_for_high_risk = 20

# Triage configuration to filter low-suspicion files
[triage]
# Enable triage phase
enabled = false
# Model for triage classification
model = "mistral-small"
# Batch size for triage requests
batch_size = 8
# Suspicion threshold (0.0-1.0)
suspicion_threshold = 0.35

# Priority configuration for file ranking
[priority]
# Enable priority scoring
enabled = true
# Boost for recently modified files (git)
git_recent_boost = 2.0
# Boost for entry-point files
entry_point_boost = 1.5
# Boost for small files
small_file_boost = 1.2

# Agent configuration
[agent]
# Enable autonomous agent mode
enabled = false
# Maximum agent turns
max_turns = 10
# Tool timeout (seconds)
tool_timeout_secs = 30
# Trusted paths for agent operations
trusted_paths = ["."]
{}
"#,
        project_name, project_path, languages_str, preset_comment
    )
}

/// Run the init command
pub fn run_init(cmd: &InitCommand, quiet: bool) -> Result<(), ScanError> {
    let target_path = &cmd.path;

    // Resolve to absolute path
    let abs_path = if target_path.is_absolute() {
        target_path.clone()
    } else {
        std::env::current_dir()
            .map_err(ScanError::IoError)?
            .join(target_path)
    };

    // Check if target exists
    if !abs_path.exists() {
        return Err(ScanError::Config {
            message: format!("Target directory does not exist: {}", abs_path.display()),
            source: None,
        });
    }

    if !abs_path.is_dir() {
        return Err(ScanError::Config {
            message: format!("Target path is not a directory: {}", abs_path.display()),
            source: None,
        });
    }

    let config_path = abs_path.join("baco.toml");

    // Check if config already exists
    if config_path.exists() && !cmd.force {
        return Err(ScanError::Config {
            message: format!(
                "baco.toml already exists at {}. Use --force to overwrite.",
                config_path.display()
            ),
            source: None,
        });
    }

    // Detect languages
    let languages = detect_languages_in_dir(&abs_path);
    let languages_vec: Vec<String> = languages.iter().cloned().collect();

    if languages_vec.is_empty() && !quiet {
        println!(
            "Warning: No recognized source files found in {}",
            abs_path.display()
        );
    }

    // Detect markers and suggest preset
    let markers = detect_project_markers(&abs_path);
    let suggested_preset = suggest_preset(&languages, &markers);

    // Get project name from directory
    let project_name = abs_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "my-project".to_string());

    // Generate config content
    let config_content = generate_config_content(
        &project_name,
        ".",
        &languages_vec,
        suggested_preset.as_deref(),
    );

    // Write config file
    fs::write(&config_path, &config_content).map_err(ScanError::IoError)?;

    // Print summary
    if !quiet {
        println!("\n{}", "═".repeat(50));
        println!("  BACO INIT - Configuration Generated");
        println!("{}", "═".repeat(50));
        println!("\n📁 Project: {}", project_name);
        println!("📂 Path: {}", abs_path.display());
        println!("📝 Config: {}", config_path.display());

        if !languages_vec.is_empty() {
            println!("\n🔤 Detected languages:");
            for lang in &languages_vec {
                println!("   • {}", lang);
            }
        }

        if let Some(preset) = &suggested_preset {
            println!(
                "\n💡 Suggested preset: {} (run 'baco preset show {}' to view)",
                preset, preset
            );
        }

        println!("\n📋 Next steps:");
        println!("   1. Set API keys (env vars or edit baco.toml):");
        println!("      export MISTRAL_API_KEY=your_key_here");
        println!("   2. Validate config: baco doctor --config baco.toml");
        println!("   3. Run scan: baco scan --config baco.toml");

        println!("\n💬 For help, run: baco doctor --config baco.toml");
        println!("📖 See config.example.toml for full documentation\n");
    } else {
        println!("{}", config_path.display());
    }

    Ok(())
}
