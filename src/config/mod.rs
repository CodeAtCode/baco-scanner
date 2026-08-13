mod env;
mod llm;
mod phases;
mod scanner;
mod tickets;

pub use env::*;
pub use llm::*;
pub use phases::*;
pub use scanner::*;
pub use tickets::*;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScannerConfig {
    #[serde(default)]
    pub project: ProjectConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub scanner: ScannerSettings,
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub tickets: TicketConfig,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub router: RouterConfig,
    #[serde(default)]
    pub aggregation: AggregationConfig,
    #[serde(default)]
    pub rulesynth: RuleSynthConfig,
    #[serde(default)]
    pub normalization: NormalizationConfig,
    #[serde(default)]
    pub cpg: CpgConfig,
    #[serde(default)]
    pub exploit: ExploitConfig,
    #[serde(default)]
    pub validate: ValidateConfig,
    #[serde(default)]
    pub vultriage: VultriageConfig,
    #[serde(default)]
    pub policy_sampling: PolicySamplingConfig,
    #[serde(default)]
    pub agent_scaffold: AgentScaffoldConfig,
    #[serde(default)]
    pub pacvd: PacvdConfig,
    #[serde(default)]
    pub agent_flow: AgentFlowConfig,
}

/// Config error with field path and TOML location information
#[derive(Debug)]
pub enum ConfigError {
    /// IO error reading config file
    Io(std::io::Error),
    /// TOML parse error with location
    Parse {
        message: String,
        line: Option<u32>,
        column: Option<u32>,
    },
    /// Validation error with field path
    Validation { field: String, message: String },
    /// Missing dependency (e.g., semgrep)
    MissingDependency {
        tool: String,
        install_hints: Vec<String>,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(err) => write!(f, "IO error: {}", err),
            ConfigError::Parse {
                message,
                line,
                column,
            } => {
                if let (Some(l), Some(c)) = (line, column) {
                    write!(
                        f,
                        "TOML parse error at line {}, column {}: {}",
                        l, c, message
                    )
                } else {
                    write!(f, "TOML parse error: {}", message)
                }
            }
            ConfigError::Validation { field, message } => {
                write!(f, "Validation error at {}: {}", field, message)
            }
            ConfigError::MissingDependency {
                tool,
                install_hints,
            } => {
                write!(f, "{} is not installed or not in PATH", tool)?;
                if !install_hints.is_empty() {
                    write!(f, "\nInstall with:")?;
                    for hint in install_hints {
                        write!(f, "\n  {}", hint)?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self {
        ConfigError::Io(err)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(err: toml::de::Error) -> Self {
        // toml::de::Error implements Display with location info like "TOML parse error at line 1, column 10"
        let msg = err.to_string();
        ConfigError::Parse {
            message: msg.clone(),
            line: None, // toml::de::Error doesn't expose line/column publicly in v0.8
            column: None,
        }
    }
}

impl ScannerConfig {
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: ScannerConfig = toml::from_str(&content)?;
        Ok(config)
    }

    fn validate_phase(phase_name: &str, phase: &LlmPhaseConfig) -> Result<(), ConfigError> {
        // If api_key is empty/None, LLM is disabled for this phase - skip validation
        if phase.api_key.as_ref().map_or(true, |k| k.is_empty()) {
            return Ok(());
        }

        if phase.base_url.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{}.base_url", phase_name),
                message: "base_url is required when API key is set".to_string(),
            });
        }
        let models = phase.get_models();
        if models.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{}.model or {}.models", phase_name, phase_name),
                message: "at least one model must be specified (use 'model' or 'models' field)"
                    .to_string(),
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        Self::validate_phase("llm.phases.discovery", &self.llm.phases.discovery)?;
        Self::validate_phase("llm.phases.verification", &self.llm.phases.verification)?;
        Self::validate_phase("llm.phases.aggregation", &self.llm.phases.aggregation)?;
        let project_path = PathBuf::from(&self.project.path);
        if !project_path.exists() {
            return Err(ConfigError::Validation {
                field: "project.path".to_string(),
                message: format!("Project path does not exist: {}", self.project.path),
            });
        }
        if which::which("semgrep").is_err() {
            return Err(ConfigError::MissingDependency {
                tool: "Semgrep".to_string(),
                install_hints: vec![
                    "brew install semgrep".to_string(),
                    "pip install semgrep".to_string(),
                ],
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectConfig {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub languages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OutputConfig {
    pub dir: String,
    #[serde(default)]
    pub format: Vec<String>,
}

// Default value functions - these need to be in mod.rs so they can be referenced
// by submodules via crate::config::default_*
pub fn default_max_concurrent() -> usize {
    4
}

pub fn default_llm_temperature() -> f32 {
    0.5
}

pub fn default_max_turns() -> u32 {
    10
}

pub fn default_tool_timeout() -> u64 {
    30
}

pub fn default_trusted_paths() -> Vec<String> {
    vec![".".to_string()]
}

pub fn default_llm_static_analysis() -> String {
    "llm_static_analysis".to_string()
}
