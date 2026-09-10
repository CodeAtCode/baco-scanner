use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::config::knowledge::HookRegistryLanguageConfig;

/// Registration of a hook to its handler
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRegistration {
    pub hook: String,
    pub handler: String,
}

/// Built-in PHP callable patterns (used when handler_patterns is None)
const BUILTIN_HANDLER_PATTERNS: &[&str] = &[
    // String callable: 'handler_name' or "handler_name"
    r"^[ \t]*[\x27\x22]([a-zA-Z_][a-zA-Z0-9_]*)[\x27\x22]",
    // Array callable: [$this, 'method']
    r"^[ \t]*\[\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*[\x27\x22]([a-zA-Z_][a-zA-Z0-9_]*)[\x27\x22]\s*\]",
    // Array callable: array( $this, 'method' )
    r"^[ \t]*array\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*[\x27\x22]([a-zA-Z_][a-zA-Z0-9_]*)[\x27\x22]\s*\)",
];

/// Extract framework-specific hook registrations from content
///
/// Uses the provided language configuration to determine:
/// - Which registration patterns to match (registrations)
/// - How to extract handler names (handler_patterns or built-ins)
/// - How to synthesize hook names when patterns lack named captures (hook_label)
///
/// Dedupes (hook, handler) pairs preserving first-seen order.
pub fn extract_hooks(
    content: &str,
    lang_cfg: &HookRegistryLanguageConfig,
) -> Vec<HookRegistration> {
    // Empty registrations → empty result
    if lang_cfg.registrations.is_empty() {
        return Vec::new();
    }

    // Compile registration patterns once
    let reg_patterns: Vec<Regex> = lang_cfg
        .registrations
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

    // Compile handler patterns once (use built-ins if not overridden)
    let default_handlers: Vec<String> = BUILTIN_HANDLER_PATTERNS
        .iter()
        .map(|s| s.to_string())
        .collect();
    let handler_cfg = lang_cfg
        .handler_patterns
        .as_ref()
        .unwrap_or(&default_handlers);
    let handler_patterns: Vec<Regex> = handler_cfg
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

    let mut registrations = Vec::new();
    let mut seen = HashSet::new();

    // Process each registration pattern
    for reg_re in &reg_patterns {
        for cap in reg_re.captures_iter(content) {
            // Try to extract hook name from named capture
            let hook: Option<String> = cap
                .name("hook")
                .map(|hook_cap| hook_cap.as_str().to_string());

            let full_match_end = cap.get(0).unwrap().end();
            let remainder = &content[full_match_end..];
            let handler_window: String = remainder.chars().take(200).collect();

            // Try each handler pattern
            let handler: Option<String> = {
                let mut found_handler = None;
                for handler_re in &handler_patterns {
                    if let Some(h_cap) = handler_re.captures(&handler_window) {
                        if let Some(handler_str) = h_cap.get(1) {
                            found_handler = Some(handler_str.as_str().to_string());
                            break;
                        }
                    }
                }
                found_handler
            };

            if let Some(handler) = handler {
                let final_hook = match hook {
                    Some(h) => h,
                    None => format!("{}_{}", lang_cfg.hook_label, handler),
                };

                let key = (final_hook.clone(), handler.clone());
                if seen.insert(key) {
                    registrations.push(HookRegistration {
                        hook: final_hook,
                        handler,
                    });
                }
            }
        }
    }

    registrations
}

/// Compute the hook map path mirroring the file_hashes.json derivation from indexing.rs
/// The path is: {output_dir}/hook_map.json
pub fn hook_map_path(output_dir: &Path) -> PathBuf {
    output_dir.join("hook_map.json")
}

/// Save hook map to JSON file
pub fn save_hook_map(path: &Path, map: &HashMap<String, Vec<String>>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(map).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

/// Load hook map from JSON file
/// Missing file returns empty map
pub fn load_hook_map(path: &Path) -> HashMap<String, Vec<String>> {
    if !path.exists() {
        return HashMap::new();
    }
    match std::fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|_| HashMap::new()),
        Err(_) => HashMap::new(),
    }
}
