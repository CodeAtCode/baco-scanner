use serde::{Deserialize, Serialize};

/// Configuration for a ticket tracking system (GitHub, GitLab, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketSystem {
    pub name: String,
    pub system_type: String,
    pub url: String,
    pub credentials: Option<String>,
}

/// Reference to a ticket in an external tracking system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketReference {
    pub ticket_id: String,
    pub ticket_url: String,
    pub system: String,
    pub status: String,
    pub title: String,
}
