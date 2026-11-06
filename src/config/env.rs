use std::collections::HashMap;
use std::env;
use std::sync::Mutex;

/// Global lock for env var operations — serializes all set_var/remove_var calls
static ENV_LOCK: Mutex<()> = Mutex::new(());

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
    if let Ok(key) = env::var("LLM_STATIC_ANALYSIS_KEY") {
        overrides.insert("static_analysis".to_string(), Some(key));
    }
    if let Ok(key) = env::var("LLM_SECURITY_AGENT_VERIFICATION_KEY") {
        overrides.insert("security_agent_verification".to_string(), Some(key));
    }
    if let Ok(key) = env::var("LLM_THREAT_MODELING_KEY") {
        overrides.insert("threat_modeling".to_string(), Some(key));
    }
    // Global fallback: LLM_API_KEY fills phases without a slot-specific key.
    if let Ok(fallback) = env::var("LLM_API_KEY") {
        for phase in [
            "discovery",
            "verification",
            "aggregation",
            "static_analysis",
            "security_agent_verification",
            "threat_modeling",
        ] {
            overrides
                .entry(phase.to_string())
                .or_insert_with(|| Some(fallback.clone()));
        }
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
                "static_analysis" => {
                    if config.llm.phases.static_analysis.api_key.is_none() {
                        config.llm.phases.static_analysis.api_key = Some(api_key);
                    }
                }
                "security_agent_verification" => {
                    if config
                        .llm
                        .phases
                        .security_agent_verification
                        .api_key
                        .is_none()
                    {
                        config.llm.phases.security_agent_verification.api_key = Some(api_key);
                    }
                }
                "threat_modeling" => {
                    if config.llm.phases.threat_modeling.api_key.is_none() {
                        config.llm.phases.threat_modeling.api_key = Some(api_key);
                    }
                }
                _ => {
                    tracing::warn!("Unknown LLM phase: {}", phase_name);
                }
            }
        }
    }

    apply_ticket_env_overrides(config);
}

fn apply_ticket_env_overrides(config: &mut crate::config::ScannerConfig) {
    for system in &mut config.tickets.systems {
        if system.system_type == "github" && system.api_key.is_none() {
            if let Ok(key) = env::var("TICKET_GITHUB_KEY") {
                system.api_key = Some(key);
            }
        } else if system.system_type == "gitlab" && system.api_key.is_none() {
            if let Ok(key) = env::var("TICKET_GITLAB_KEY") {
                system.api_key = Some(key);
            }
        }
    }
}

/// Guard for environment variables that auto-cleans on drop
pub struct EnvVarGuard {
    vars: HashMap<String, Option<String>>,
    /// Holds the lock for the duration of the guard's lifetime
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvVarGuard {
    pub fn set(vars: &[(&str, &str)]) -> Self {
        // Acquire the lock before setting any vars
        let lock = ENV_LOCK.lock().unwrap();
        let mut previous = HashMap::new();
        for &(key, value) in vars {
            let old_value = std::env::var(key).ok();
            unsafe { std::env::set_var(key, value) };
            previous.insert(key.to_string(), old_value);
        }
        Self {
            vars: previous,
            _lock: lock,
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // Lock is still held here, so restoration is serialized
        for (key, old_value) in &self.vars {
            match old_value {
                Some(v) => unsafe { std::env::set_var(key, v) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
        // Lock is released when _lock is dropped
    }
}
