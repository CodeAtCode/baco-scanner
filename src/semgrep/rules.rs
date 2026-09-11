use crate::findings::Severity;

#[derive(Clone)]
pub struct SemgrepRunner {
    pub rulesets: Vec<String>,
    pub exclude_rules: Vec<String>,
    /// Inline rule YAML documents (preset `custom_rules`), materialized to
    /// temp .yml files at scan time.
    pub custom_rules: Vec<String>,
    /// Project languages for deriving default rulesets
    pub languages: Vec<String>,
}

impl SemgrepRunner {
    pub fn new(rulesets: Vec<String>, exclude_rules: Vec<String>) -> Self {
        Self {
            rulesets,
            exclude_rules,
            custom_rules: Vec::new(),
            languages: Vec::new(),
        }
    }

    /// Builder: set project languages for default ruleset derivation
    pub fn with_languages(mut self, languages: Vec<String>) -> Self {
        self.languages = languages;
        self
    }

    /// Builder: attach inline rule YAML documents from preset `custom_rules`.
    pub fn with_custom_rules(mut self, custom_rules: Vec<String>) -> Self {
        self.custom_rules = custom_rules;
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
        super::parser::parse_json_output(json, &self.exclude_rules)
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
    match check_id.to_lowercase().as_str() {
        s if s.contains("critical") => Severity::Critical,
        s if s.contains("high") => Severity::High,
        s if s.contains("medium") => Severity::Medium,
        s if s.contains("low") => Severity::Low,
        _ => Severity::Info,
    }
}
