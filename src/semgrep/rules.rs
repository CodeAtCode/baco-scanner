use crate::findings::Severity;

/// Per-file semgrep timeout in seconds (passed to `--timeout` flag).
pub const DEFAULT_SEMGREP_TIMEOUT_SECS: u64 = 300;

/// Wall-clock timeout for the entire semgrep run in seconds.
/// Separate from `DEFAULT_SEMGREP_TIMEOUT_SECS` to avoid aborting
/// large projects that legitimately need more total time.
pub const DEFAULT_SEMGREP_WALL_CLOCK_SECS: u64 = 1800;

/// Bundled taint-mode rules for Python (derived from presets/oss-python.toml)
const TAINT_PYTHON_RULES: &str = include_str!("rules/taint-python.yml");

/// Bundled taint-mode rules for JavaScript/TypeScript (derived from presets/javascript.toml)
const TAINT_JAVASCRIPT_RULES: &str = include_str!("rules/taint-javascript.yml");

/// Bundled taint-mode rules for Go (derived from presets/go.toml)
const TAINT_GO_RULES: &str = include_str!("rules/taint-go.yml");

/// Bundled taint-mode rules for PHP
const TAINT_PHP_RULES: &str = include_str!("rules/taint-php.yml");

/// Bundled taint-mode rules for C/C++
const TAINT_C_RULES: &str = include_str!("rules/taint-c.yml");

/// Bundled taint-mode rules for Java
const TAINT_JAVA_RULES: &str = include_str!("rules/taint-java.yml");

/// Bundled taint-mode rules for Ruby
const TAINT_RUBY_RULES: &str = include_str!("rules/taint-ruby.yml");

/// Bundled taint-mode rules for C#
const TAINT_CSHARP_RULES: &str = include_str!("rules/taint-csharp.yml");

#[derive(Clone)]
pub struct SemgrepRunner {
    pub rulesets: Vec<String>,
    pub exclude_rules: Vec<String>,
    /// Per-file timeout: passed to semgrep `--timeout` flag.
    pub timeout_secs: u64,
    /// Wall-clock timeout for the entire semgrep run (client-side).
    pub wall_clock_timeout_secs: u64,
    /// Inline rule YAML documents (preset `custom_rules`), materialized to
    /// temp .yml files at scan time.
    pub custom_rules: Vec<String>,
    /// Project languages for deriving default rulesets
    pub languages: Vec<String>,
    /// Max file size for semgrep targets in bytes (passed as --max-target-bytes)
    pub max_target_bytes: Option<u64>,
    /// When true, pass `--no-git-ignore` to semgrep to scan files ignored by
    /// `.gitignore` (git-ignored and untracked files). Does NOT bypass the
    /// built-in `.semgrepignore`, so directories like `tests/` stay skipped.
    pub force_scan: bool,
}

impl SemgrepRunner {
    pub fn new(rulesets: Vec<String>, exclude_rules: Vec<String>) -> Self {
        Self {
            rulesets,
            exclude_rules,
            timeout_secs: DEFAULT_SEMGREP_TIMEOUT_SECS,
            wall_clock_timeout_secs: DEFAULT_SEMGREP_WALL_CLOCK_SECS,
            custom_rules: Vec::new(),
            languages: Vec::new(),
            max_target_bytes: None,
            force_scan: false,
        }
    }

    /// Builder: set project languages for default ruleset derivation
    pub fn with_languages(mut self, languages: Vec<String>) -> Self {
        self.languages = languages;
        self
    }

    /// Builder: set per-file timeout in seconds.
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Builder: set wall-clock timeout for the entire semgrep run.
    pub fn with_wall_clock_timeout(mut self, wall_clock_timeout_secs: u64) -> Self {
        self.wall_clock_timeout_secs = wall_clock_timeout_secs;
        self
    }

    /// Builder: attach inline rule YAML documents from preset `custom_rules`.
    pub fn with_custom_rules(mut self, custom_rules: Vec<String>) -> Self {
        self.custom_rules = custom_rules;
        self
    }

    /// Builder: set max target file size in bytes (passed as --max-target-bytes).
    pub fn with_max_target_bytes(mut self, max_target_bytes: u64) -> Self {
        self.max_target_bytes = Some(max_target_bytes);
        self
    }

    /// Builder: enable `--no-git-ignore` flag to scan normally ignored files.
    pub fn with_force_scan(mut self, force_scan: bool) -> Self {
        self.force_scan = force_scan;
        self
    }

    /// Derive default rulesets from project languages when rulesets is empty.
    /// Returns a new ruleset list that may include defaults.
    pub fn derive_default_rulesets(&self) -> Vec<String> {
        if !self.rulesets.is_empty() {
            // Explicit rulesets take precedence - return as-is
            return self.rulesets.clone();
        }

        // Derive defaults from languages
        let mut defaults = std::collections::HashSet::new();
        for lang in &self.languages {
            match lang.to_lowercase().as_str() {
                "python" => {
                    defaults.insert("p/python".to_string());
                }
                "javascript" | "js" => {
                    defaults.insert("p/javascript".to_string());
                }
                "php" => {
                    defaults.insert("p/php".to_string());
                }
                "c" | "cpp" | "cxx" => {
                    defaults.insert("p/c".to_string());
                }
                "go" => {
                    defaults.insert("p/golang".to_string());
                }
                "java" => {
                    defaults.insert("p/java".to_string());
                }
                "ruby" => {
                    defaults.insert("p/ruby".to_string());
                }
                "csharp" | "cs" => {
                    defaults.insert("p/csharp".to_string());
                }
                _ => { /* No default for unknown languages */ }
            }
        }

        defaults.into_iter().collect()
    }

    /// Derive default taint-mode custom rules from project languages.
    /// Returns inline YAML documents (one per language) so data-flow vulnerabilities
    /// are detected by default. Does NOT suppress derived rules when explicit custom
    /// rules are present — explicit rules are merged with derived rules, with explicit
    /// rules taking precedence on id collision.
    pub fn derive_default_custom_rules(&self) -> Vec<String> {
        let mut defaults = Vec::new();
        for lang in &self.languages {
            match lang.to_lowercase().as_str() {
                "python" => defaults.push(TAINT_PYTHON_RULES.to_string()),
                "javascript" | "js" | "typescript" | "ts" => {
                    defaults.push(TAINT_JAVASCRIPT_RULES.to_string())
                }
                "go" => defaults.push(TAINT_GO_RULES.to_string()),
                "php" => defaults.push(TAINT_PHP_RULES.to_string()),
                "c" | "cpp" | "cxx" => defaults.push(TAINT_C_RULES.to_string()),
                "java" => defaults.push(TAINT_JAVA_RULES.to_string()),
                "ruby" => defaults.push(TAINT_RUBY_RULES.to_string()),
                "csharp" | "c#" | "cs" => defaults.push(TAINT_CSHARP_RULES.to_string()),
                _ => {}
            }
        }
        // Dedup: a project with both "javascript" and "typescript" should get
        // the JS taint file once, not twice.
        defaults.sort();
        defaults.dedup();
        defaults
    }

    /// Check if a rule check_id should be excluded based on exclude_rules patterns.
    /// Supports exact match and prefix match (e.g., "python.lang" excludes all "python.lang.*" rules).
    pub fn should_exclude_rule(&self, check_id: &str) -> bool {
        self.exclude_rules.iter().any(|pattern| {
            // Exact match
            if check_id == pattern {
                return true;
            }
            // Prefix match (e.g., "python.lang" matches "python.lang.security")
            if check_id.starts_with(pattern) {
                return true;
            }
            false
        })
    }

    /// Convenience method that calls the parser module's parse_json_output function
    pub fn parse_json_output(
        &self,
        json: &[u8],
    ) -> Result<Vec<crate::findings::VulnerabilityFinding>, String> {
        super::parser::parse_json_output(json, &self.exclude_rules, &[])
    }
}

/// Raw finding structure before aggregation
pub struct RawFinding {
    pub path: String,
    pub line: u32,
    pub end_line: u32,
    pub severity: Severity,
    pub cwe_id: Option<String>,
    pub message: Option<String>,
}

/// Map check_id to severity based on keyword matching.
/// Returns `None` when no keyword matches, so the parser can distinguish
/// a real keyword-derived severity (which may upgrade an explicit
/// `extra.severity`) from an unknown fallback (which must not).
pub fn parse_severity(check_id: &str) -> Option<Severity> {
    match check_id.to_lowercase().as_str() {
        s if s.contains("critical") => Some(Severity::Critical),
        s if s.contains("high") => Some(Severity::High),
        s if s.contains("medium") => Some(Severity::Medium),
        s if s.contains("low") => Some(Severity::Low),
        s if s.contains("info") => Some(Severity::Info),
        _ => None,
    }
}

/// Collect rule IDs from a list of YAML documents.
/// Each document is expected to have a `rules` list with `id` fields.
/// Returns a BTreeSet of all rule IDs found. Malformed documents are
/// skipped with a warning instead of aborting the entire collection,
/// so a single bad rule does not suppress all taint rules.
pub fn collect_rule_ids(docs: &[String]) -> Result<std::collections::BTreeSet<String>, String> {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Rule {
        id: String,
    }

    #[derive(Deserialize)]
    struct RulesDoc {
        rules: Option<Vec<Rule>>,
    }

    let mut ids = std::collections::BTreeSet::new();

    for (i, doc) in docs.iter().enumerate() {
        match serde_yaml::from_str::<RulesDoc>(doc) {
            Ok(parsed) => {
                if let Some(rules) = parsed.rules {
                    for rule in rules {
                        ids.insert(rule.id);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Skipping malformed custom rule at index {}: {}", i, e);
            }
        }
    }

    Ok(ids)
}

/// Filter rules from a YAML document, excluding those whose IDs are in the exclude set.
/// Returns Ok(None) if no rules remain after filtering or the document is malformed,
/// Ok(Some(string)) with the re-serialized document otherwise. Malformed documents
/// are skipped with a warning instead of aborting the entire scan.
pub fn filter_rules_excluding_ids(
    doc: &str,
    exclude: &std::collections::BTreeSet<String>,
) -> Result<Option<String>, String> {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    struct Rule {
        id: String,
        #[serde(flatten)]
        rest: serde_yaml::Value,
    }

    #[derive(Deserialize, Serialize)]
    struct RulesDoc {
        rules: Vec<Rule>,
        #[serde(flatten)]
        rest: std::collections::HashMap<String, serde_yaml::Value>,
    }

    let parsed: RulesDoc = match serde_yaml::from_str(doc) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Skipping malformed derived taint rule document: {}", e);
            return Ok(None);
        }
    };

    let filtered: Vec<Rule> = parsed
        .rules
        .into_iter()
        .filter(|r| !exclude.contains(&r.id))
        .collect();

    if filtered.is_empty() {
        return Ok(None);
    }

    let output = RulesDoc {
        rules: filtered,
        rest: parsed.rest,
    };

    let serialized = serde_yaml::to_string(&output)
        .map_err(|e| format!("Failed to serialize filtered rules: {}", e))?;

    Ok(Some(serialized))
}
