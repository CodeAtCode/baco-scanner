use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::config::knowledge::HookRegistryLanguageConfig;

/// Registration of a hook to its handler
///
/// Both names are persisted. The hook name is what separates an authenticated
/// entry point (`wp_ajax_save`) from an unauthenticated one
/// (`wp_ajax_nopriv_save`), and that difference sets the severity of a missing
/// security primitive. Storing only the handler made the two indistinguishable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookRegistration {
    pub hook: String,
    pub handler: String,
}

/// A hook registration with no security primitive reachable from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnprotectedHook {
    pub hook: String,
    pub handler: String,
    /// Line where the handler function is declared, when the file could be parsed.
    pub line: usize,
    /// True when the hook is reachable without authentication
    /// (`wp_ajax_nopriv_*`, `admin_post_nopriv_*`).
    pub unauthenticated: bool,
}

/// How many levels of callee bodies to search after the handler's own body.
///
/// One level covers the common shape where an entry point delegates to a helper
/// that does the authorisation. Going deeper needs call-graph resolution this
/// layer does not have: `extract_call_sites` is a syntactic scan, so at depth it
/// would follow calls that never execute and miss ones reached through variables.
const CALLEE_SEARCH_DEPTH: usize = 2;

/// Find hook registrations whose handler cannot reach any security primitive.
///
/// This is a static reachability check over the file, not an inference: the
/// handler body is extracted, the functions it calls are extracted, and a
/// primitive counts only if its name literally appears in one of those bodies.
/// A handler that is never declared in this file is left alone rather than
/// reported, because the file that defines it is scanned on its own.
pub fn find_unprotected_hooks(
    content: &str,
    registrations: &[HookRegistration],
    primitives: &[String],
) -> Vec<UnprotectedHook> {
    if registrations.is_empty() || primitives.is_empty() {
        return Vec::new();
    }

    let functions = parse_functions(content);
    let mut unprotected = Vec::new();

    for reg in registrations {
        let Some((handler_line, handler_body)) = functions.get(&reg.handler) else {
            // Handler declared elsewhere (or via a callable array we cannot
            // resolve). Reporting it would invent a finding with no evidence.
            continue;
        };

        if body_has_primitive(handler_body, primitives) {
            continue;
        }

        if !calls_reach_primitive(handler_body, &functions, primitives, CALLEE_SEARCH_DEPTH) {
            unprotected.push(UnprotectedHook {
                hook: reg.hook.clone(),
                handler: reg.handler.clone(),
                line: *handler_line,
                unauthenticated: is_unauthenticated_hook(&reg.hook),
            });
        }
    }

    unprotected
}

/// Hooks reachable by an unauthenticated request.
///
/// `wp_ajax_` and `admin_post_` require a logged-in user, so a missing
/// primitive there is a CSRF surface. The `_nopriv_` variants require nothing,
/// so the same gap is an unauthenticated write.
fn is_unauthenticated_hook(hook: &str) -> bool {
    hook.contains("wp_ajax_nopriv_") || hook.contains("admin_post_nopriv_")
}

/// Whether the body contains any of the primitives.
///
/// Public because the verifier needs the same question answered the same way:
/// a finding confirmed here must be refutable here, or the two phases disagree
/// about what a primitive is.
pub fn body_has_primitive(body: &str, primitives: &[String]) -> bool {
    primitives
        .iter()
        .any(|p| !p.is_empty() && body.contains(p.as_str()))
}

/// Search the bodies of the functions `body` calls, up to `depth` levels.
fn calls_reach_primitive(
    body: &str,
    functions: &std::collections::HashMap<String, (usize, String)>,
    primitives: &[String],
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    for site in crate::context::callee_walker::extract_call_sites(body) {
        if let Some((_, callee_body)) = functions.get(&site.callee) {
            if body_has_primitive(callee_body, primitives) {
                return true;
            }
            if calls_reach_primitive(callee_body, functions, primitives, depth - 1) {
                return true;
            }
        }
    }
    false
}

/// Extract every top-level function body from PHP-ish source.
///
/// Brace matching from the declaration's opening brace, skipping braces inside
/// strings and comments. A regex cannot do this: a `}` inside a string literal
/// would end the body early and the check would then look at a fragment.
fn parse_functions(content: &str) -> std::collections::HashMap<String, (usize, String)> {
    let chars: Vec<char> = content.chars().collect();
    // byte offset of each char index, for slicing without byte/char confusion
    let mut offsets: Vec<usize> = Vec::with_capacity(chars.len() + 1);
    let mut o = 0;
    for c in &chars {
        offsets.push(o);
        o += c.len_utf8();
    }
    offsets.push(o);

    let decl = Regex::new(
        r"(?s)function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*(?::\s*[a-zA-Z_\\][a-zA-Z0-9_\\]*\s*)?\{",
    )
    .expect("function declaration regex is valid");

    let mut functions = std::collections::HashMap::new();
    for caps in decl.captures_iter(content) {
        let whole = caps.get(0).expect("group 0 of a capture always exists");
        let name = caps
            .get(1)
            .expect("group 1 is required")
            .as_str()
            .to_string();

        // Walk from the opening brace to its match, tracking lexical state.
        let start_char = whole.end() - 1;
        let mut depth_brace = 0usize;
        let mut i = start_char;
        let mut state = LexState::Code;
        let mut end_char = chars.len();
        while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            match state {
                LexState::Code => match c {
                    '\'' | '"' => state = LexState::InString(c),
                    '/' if next == Some('/') => {
                        state = LexState::InLineComment;
                        i += 1;
                    }
                    '#' => state = LexState::InLineComment,
                    '/' if next == Some('*') => {
                        state = LexState::InBlockComment;
                        i += 1;
                    }
                    '{' => depth_brace += 1,
                    '}' => {
                        depth_brace -= 1;
                        if depth_brace == 0 {
                            end_char = i + 1;
                            break;
                        }
                    }
                    _ => {}
                },
                LexState::InString(quote) => {
                    if c == '\\' {
                        i += 1;
                    } else if c == quote {
                        state = LexState::Code;
                    }
                }
                LexState::InLineComment => {
                    if c == '\n' {
                        state = LexState::Code;
                    }
                }
                LexState::InBlockComment => {
                    if c == '*' && next == Some('/') {
                        state = LexState::Code;
                        i += 1;
                    }
                }
            }
            i += 1;
        }

        let body_start = offsets[start_char];
        let body_end = offsets[end_char.min(chars.len())];
        let body = content[body_start..body_end].to_string();
        // The prefix ends just before the opening brace, and `lines()` counts the
        // lines it contains -- which is already the 1-based line the brace is on.
        let line = content[..body_start].lines().count().max(1);
        functions.entry(name).or_insert((line, body));
    }
    functions
}

enum LexState {
    Code,
    InString(char),
    InLineComment,
    InBlockComment,
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
///
/// Writes to a sibling temporary file and renames it into place. A plain
/// `fs::write` truncates the target first, so an interrupted scan left a
/// half-written file that then deserialised to an empty map on resume.
pub fn save_hook_map(
    path: &Path,
    map: &HashMap<String, Vec<HookRegistration>>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(map).map_err(std::io::Error::other)?;

    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Do not leave the temporary behind on a failed rename.
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Load hook map from JSON file
///
/// A missing file is legitimately empty. A file that exists but cannot be read
/// or parsed is a different condition: it used to come back as an empty map
/// with no warning, so a corrupt map -- which an interrupted save could
/// produce -- silently erased every registered entry point from the scan.
pub fn load_hook_map(path: &Path) -> HashMap<String, Vec<HookRegistration>> {
    if !path.exists() {
        return HashMap::new();
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "Hook map at {} could not be read ({}); proceeding with no hooks. \
                 Registered entry points will be missing from this scan.",
                path.display(),
                e
            );
            return HashMap::new();
        }
    };
    match serde_json::from_str(&content) {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(
                "Hook map at {} is not valid JSON ({}); proceeding with no hooks. \
                 Registered entry points will be missing from this scan.",
                path.display(),
                e
            );
            HashMap::new()
        }
    }
}
