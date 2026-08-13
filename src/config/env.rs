use std::collections::HashMap;
use std::env;

fn load_env_api_keys() -> HashMap<String, Option<String>> {
    let mut overrides = HashMap::new();
    if let Ok(key) = env::var("LLM_DISCOVERY_KEY") {
        overrides.insert("discovery".to_string(), Some(key));
    }
    if let Ok(key) = env::var("LLM_VERIFICATION_KEY") {
        overrides.insert("verification".to_string(), Some(key));
    }
    if let Ok(key) = env::var("LLM_AGGREGATION_KEY") {
        overrides.insert("aggregation".to_string(), Some(key));
    }
    overrides
}

pub fn apply_env_overrides(config: &mut crate::config::ScannerConfig) {
    let env_keys = load_env_api_keys();
    for (phase_name, override_key) in env_keys {
        if let Some(api_key) = override_key {
            match phase_name.as_str() {
                "discovery" => {
                    if config.llm.phases.discovery.api_key.is_none() {
                        config.llm.phases.discovery.api_key = Some(api_key);
                    }
                }
                "verification" => {
                    if config.llm.phases.verification.api_key.is_none() {
                        config.llm.phases.verification.api_key = Some(api_key);
                    }
                }
                "aggregation" => {
                    if config.llm.phases.aggregation.api_key.is_none() {
                        config.llm.phases.aggregation.api_key = Some(api_key);
                    }
                }
                _ => {
                    tracing::warn!("Unknown LLM phase: {}", phase_name);
                }
            }
        }
    }
}

/// Guard for environment variables that auto-cleans on drop
pub struct EnvVarGuard {
    vars: HashMap<String, Option<String>>,
}

impl EnvVarGuard {
    pub fn set(vars: &[(&str, &str)]) -> Self {
        let mut previous = HashMap::new();
        for &(key, value) in vars {
            let old_value = std::env::var(key).ok();
            std::env::set_var(key, value);
            previous.insert(key.to_string(), old_value);
        }
        Self { vars: previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, old_value) in &self.vars {
            match old_value {
                Some(v) => unsafe { std::env::set_var(key, v) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }
}
