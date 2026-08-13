use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TicketConfig {
    #[serde(default)]
    pub systems: Vec<TicketSystemConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TicketSystemConfig {
    pub system_type: String,
    pub url: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
}
