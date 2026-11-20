//! Embedded default prompt templates for all BACO phases and project types.
//! These templates can be overridden via config.toml [phases.phase_name] sections.

use std::collections::HashMap;

/// Map CWE ID to hunt domain name
/// Returns Some(domain_name) if the CWE has a corresponding hunt prompt, None otherwise
pub fn cwe_to_hunt_domain(cwe_id: &str) -> Option<&'static str> {
    match cwe_id {
        "CWE-89" | "CWE-78" | "CWE-90" | "CWE-119" => Some("injection"), // SQL, command, LDAP injection
        "CWE-79" | "CWE-80" => Some("xss"),                              // Cross-Site Scripting
        "CWE-287" | "CWE-285" | "CWE-290" => Some("auth"), // Authentication/Authorization
        "CWE-22" | "CWE-23" | "CWE-36" => Some("path_traversal"), // Path traversal
        "CWE-327" | "CWE-328" | "CWE-757" => Some("crypto"), // Cryptographic weaknesses
        "CWE-400" | "CWE-770" | "CWE-190" => Some("resource"), // Resource handling
        "CWE-502" | "CWE-503" | "CWE-20" => Some("deserialization"), // Insecure deserialization
        _ => None,
    }
}

/// Get hunt prompt content for a domain from loaded hunt prompts
pub fn get_hunt_prompt(domain: &str, hunt_prompts: &HashMap<String, String>) -> Option<String> {
    hunt_prompts.get(domain).filter(|s| !s.is_empty()).cloned()
}

/// All 11 core BACO phases plus the six-phase orchestration variants
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum BacoPhase {
    Indexing,
    Semgrep,
    LlmStaticAnalysis,
    LlmDiscovery,
    LlmVerification,
    TicketCrossRef,
    GitAnalysis,
    CrossFileAnalysis,
    ConfidenceScoring,
    AiAggregation,
    Reporting,
    // six-phase orchestration variants
    Hunt,
    Validate,
}

/// All project type categories
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectType {
    CLI,
    Web,
    Library,
    Embedded,
    Firmware,
    Desktop,
}

impl std::fmt::Display for BacoPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BacoPhase::Indexing => write!(f, "indexing"),
            BacoPhase::Semgrep => write!(f, "semgrep"),
            BacoPhase::LlmStaticAnalysis => write!(f, "llm_static_analysis"),
            BacoPhase::LlmDiscovery => write!(f, "llm_discovery"),
            BacoPhase::LlmVerification => write!(f, "llm_verification"),
            BacoPhase::TicketCrossRef => write!(f, "ticket_crossref"),
            BacoPhase::GitAnalysis => write!(f, "git_analysis"),
            BacoPhase::CrossFileAnalysis => write!(f, "cross_file_analysis"),
            BacoPhase::ConfidenceScoring => write!(f, "confidence_scoring"),
            BacoPhase::AiAggregation => write!(f, "ai_aggregation"),
            BacoPhase::Reporting => write!(f, "reporting"),
            // six-phase orchestration variants
            BacoPhase::Hunt => write!(f, "hunt"),
            BacoPhase::Validate => write!(f, "validate"),
        }
    }
}

impl std::fmt::Display for ProjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProjectType::CLI => write!(f, "cli"),
            ProjectType::Web => write!(f, "web"),
            ProjectType::Library => write!(f, "library"),
            ProjectType::Embedded => write!(f, "embedded"),
            ProjectType::Firmware => write!(f, "firmware"),
            ProjectType::Desktop => write!(f, "desktop"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TemplateVariables(pub HashMap<String, String>);

impl TemplateVariables {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: String, value: String) {
        self.0.insert(key, value);
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Embedded default prompts for all BACO phases
///
/// These templates follow the format:
/// - {variable_name} placeholders for dynamic content
/// - %%VAR%% format for legacy compatibility
#[derive(Debug)]
pub struct DefaultPrompts {
    pub indexing: String,
    pub semgrep: String,
    pub llm_static_analysis: String,
    pub llm_discovery: String,
    pub llm_verification: String,
    pub ticket_crossref: String,
    pub git_analysis: String,
    pub cross_file_analysis: String,
    pub confidence_scoring: String,
    pub ai_aggregation: String,
    pub reporting: String,
}

impl Default for DefaultPrompts {
    fn default() -> Self {
        Self {
            indexing: Self::indexing_template(),
            semgrep: Self::semgrep_template(),
            llm_static_analysis: Self::llm_static_analysis_template(),
            llm_discovery: Self::llm_discovery_template(),
            llm_verification: Self::llm_verification_template(),
            ticket_crossref: Self::ticket_crossref_template(),
            git_analysis: Self::git_analysis_template(),
            cross_file_analysis: Self::cross_file_analysis_template(),
            confidence_scoring: Self::confidence_scoring_template(),
            ai_aggregation: Self::ai_aggregation_template(),
            reporting: Self::reporting_template(),
        }
    }
}

/// The built-in prompt for a phase, taken from the file it stands in for.
///
/// `prompts/phases/*.md` is read from disk at run time so an operator can edit a
/// prompt without rebuilding. This embeds the *same* file, so the fallback used
/// when that read fails cannot drift from the file — and cannot be a stub, which
/// two of them had become.
fn bundled_prompt(markdown: &str) -> String {
    markdown.trim().to_string()
}

impl DefaultPrompts {
    fn indexing_template() -> String {
        bundled_prompt(include_str!("../../prompts/phases/indexing.md"))
    }

    fn semgrep_template() -> String {
        bundled_prompt(include_str!("../../prompts/phases/semgrep.md"))
    }

    fn llm_static_analysis_template() -> String {
        bundled_prompt(include_str!("../../prompts/phases/llm_static_analysis.md"))
    }

    fn llm_discovery_template() -> String {
        bundled_prompt(include_str!("../../prompts/phases/llm_discovery.md"))
    }

    /// Fallback template for llm_verification prompt.
    /// PRIMARY SOURCE: prompts/phases/llm_verification.md is loaded at runtime by PromptEngine.
    /// This template is ONLY used if the .md file is missing or empty.
    /// If you change the verification prompt, update the .md file first, then sync this fallback.
    fn llm_verification_template() -> String {
        bundled_prompt(include_str!("../../prompts/phases/llm_verification.md"))
    }

    fn ticket_crossref_template() -> String {
        bundled_prompt(include_str!("../../prompts/phases/ticket_crossref.md"))
    }

    fn git_analysis_template() -> String {
        bundled_prompt(include_str!("../../prompts/phases/git_analysis.md"))
    }

    fn cross_file_analysis_template() -> String {
        bundled_prompt(include_str!("../../prompts/phases/cross_file_analysis.md"))
    }

    fn confidence_scoring_template() -> String {
        bundled_prompt(include_str!("../../prompts/phases/confidence_scoring.md"))
    }

    fn ai_aggregation_template() -> String {
        bundled_prompt(include_str!("../../prompts/phases/ai_aggregation.md"))
    }

    fn reporting_template() -> String {
        bundled_prompt(include_str!("../../prompts/phases/reporting.md"))
    }
}

/// Get default prompt for a phase, applying project type customization
pub fn get_default_prompt(phase: &BacoPhase, _project_type: &ProjectType) -> String {
    let defaults = DefaultPrompts::default();
    match phase {
        BacoPhase::Indexing => defaults.indexing,
        BacoPhase::Semgrep => defaults.semgrep,
        BacoPhase::LlmStaticAnalysis => defaults.llm_static_analysis,
        BacoPhase::LlmDiscovery => defaults.llm_discovery,
        BacoPhase::LlmVerification => defaults.llm_verification,
        BacoPhase::TicketCrossRef => defaults.ticket_crossref,
        BacoPhase::GitAnalysis => defaults.git_analysis,
        BacoPhase::CrossFileAnalysis => defaults.cross_file_analysis,
        BacoPhase::ConfidenceScoring => defaults.confidence_scoring,
        BacoPhase::AiAggregation => defaults.ai_aggregation,
        BacoPhase::Reporting => defaults.reporting,
        // six-phase orchestration - use generic prompts
        BacoPhase::Hunt => defaults.llm_discovery,
        BacoPhase::Validate => defaults.llm_verification,
    }
}

/// Get all default prompts
pub fn get_all_defaults() -> DefaultPrompts {
    DefaultPrompts::default()
}

// ============================================================================
// Domain-specific hunt prompts loaded from prompts/hunt/
// ============================================================================

/// Render a template string by substituting {{VAR}} placeholders with values from TemplateVariables
pub fn render_template(template: &str, variables: &TemplateVariables) -> String {
    let mut result = template.to_string();
    for (key, value) in &variables.0 {
        let placeholder_braces = format!("{{{{{}}}}}", key);
        let placeholder_percent = format!("%%{}%%", key);
        result = result.replace(&placeholder_braces, value);
        result = result.replace(&placeholder_percent, value);
    }
    result
}

/// Get all variable placeholders from a template string
pub fn get_template_variables(template: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let mut start = 0;
    while let Some(open_pos) = template[start..].find("{{") {
        let abs_open = start + open_pos;
        if let Some(close_pos) = template[abs_open + 2..].find("}}") {
            let abs_close = abs_open + 2 + close_pos;
            let var_name = &template[abs_open + 2..abs_close];
            if !vars.contains(&var_name.to_string()) {
                vars.push(var_name.to_string());
            }
            start = abs_close + 2;
        } else {
            break;
        }
    }
    start = 0;
    while let Some(open_pos) = template[start..].find("%%") {
        let abs_open = start + open_pos;
        if let Some(close_pos) = template[abs_open + 2..].find("%%") {
            let abs_close = abs_open + 2 + close_pos;
            let var_name = &template[abs_open + 2..abs_close];
            if !vars.contains(&var_name.to_string()) {
                vars.push(var_name.to_string());
            }
            start = abs_close + 2;
        } else {
            break;
        }
    }
    vars
}
