use crate::findings::Severity;

/// Default per-run semgrep timeout (client side) in seconds.
pub const DEFAULT_SEMGREP_TIMEOUT_SECS: u64 = 300;

/// Bundled taint-mode rules for Python (derived from presets/oss-python.toml)
const TAINT_PYTHON_RULES: &str = include_str!("rules/taint-python.yml");

/// Bundled taint-mode rules for JavaScript/TypeScript (derived from presets/javascript.toml)
const TAINT_JAVASCRIPT_RULES: &str = include_str!("rules/taint-javascript.yml");

/// Bundled taint-mode rules for Go (derived from presets/go.toml)
const TAINT_GO_RULES: &str = include_str!("rules/taint-go.yml");

#[derive(Clone)]
pub struct SemgrepRunner {
    pub rulesets: Vec<String>,
    pub exclude_rules: Vec<String>,
    /// Per-run timeout: passed to semgrep `--timeout` and enforced client-side.
    pub timeout_secs: u64,
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

    /// Builder: set per-run timeout in seconds.
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
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
                _ => { /* No default for unknown languages */ }
            }
        }

        defaults.into_iter().collect()
    }

    /// Derive default taint-mode custom rules from project languages when
    /// `custom_rules` is empty. Returns inline YAML documents (one per language)
    /// so data-flow vulnerabilities are detected by default.
    pub fn derive_default_custom_rules(&self) -> Vec<String> {
        if !self.custom_rules.is_empty() {
            // Explicit custom rules take precedence — return none.
            return Vec::new();
        }
        let mut defaults = Vec::new();
        for lang in &self.languages {
            match lang.to_lowercase().as_str() {
                "python" => defaults.push(TAINT_PYTHON_RULES.to_string()),
                "javascript" | "js" | "typescript" | "ts" => {
                    defaults.push(TAINT_JAVASCRIPT_RULES.to_string())
                }
                "go" => defaults.push(TAINT_GO_RULES.to_string()),
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

/// Map check_id to severity based on keyword matching
pub fn parse_severity(check_id: &str) -> Severity {
    // Keyword-based matching (substring), preserve raise-only semantics
    match check_id.to_lowercase().as_str() {
        s if s.contains("critical") => Severity::Critical,
        s if s.contains("high") => Severity::High,
        s if s.contains("medium") => Severity::Medium,
        s if s.contains("low") => Severity::Low,
        _ => Severity::Info,
    }
}
