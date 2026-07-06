//! Unit tests for src/tickets.rs
//!
//! Covers:
//! - TicketSystem and TicketSearcher initialization
//! - Multiple system configurations
//! - Credential handling

use baco::tickets::*;

#[test]
fn test_ticket_searcher_new_empty_systems() {
    let systems = vec![];
    let _searcher = TicketSearcher::new(systems);
    
    // Just test that creation doesn't panic
}

#[test]
fn test_ticket_searcher_new_with_systems() {
    let systems = vec![
        TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        },
    ];
    let _searcher = TicketSearcher::new(systems);
    
    // Just test that creation doesn't panic
}

#[test]
fn test_ticket_system_default_values() {
    let system = TicketSystem {
        name: "Test".to_string(),
        system_type: "github".to_string(),
        url: "https://test.com".to_string(),
        credentials: None,
    };
    
    assert_eq!(system.name, "Test");
    assert_eq!(system.system_type, "github");
    assert!(system.credentials.is_none());
}

#[test]
fn test_ticket_searcher_with_gitlab_system() {
    let systems = vec![
        TicketSystem {
            name: "GitLab".to_string(),
            system_type: "gitlab".to_string(),
            url: "https://gitlab.com".to_string(),
            credentials: None,
        },
    ];
    let _searcher = TicketSearcher::new(systems);
    
    // Just test that creation doesn't panic
}

#[test]
fn test_ticket_searcher_with_unknown_system_type() {
    let systems = vec![
        TicketSystem {
            name: "Unknown".to_string(),
            system_type: "jira".to_string(),
            url: "https://jira.example.com".to_string(),
            credentials: None,
        },
    ];
    let _searcher = TicketSearcher::new(systems);
    
    // Just test that creation doesn't panic
}

#[test]
fn test_ticket_system_multiple_systems() {
    let systems = [
        TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        },
        TicketSystem {
            name: "GitLab".to_string(),
            system_type: "gitlab".to_string(),
            url: "https://gitlab.com".to_string(),
            credentials: None,
        },
        TicketSystem {
            name: "Jira".to_string(),
            system_type: "jira".to_string(),
            url: "https://jira.example.com".to_string(),
            credentials: None,
        },
    ];
    
    assert_eq!(systems.len(), 3);
    assert_eq!(systems[0].name, "GitHub");
    assert_eq!(systems[1].name, "GitLab");
    assert_eq!(systems[2].name, "Jira");
}

#[test]
fn test_ticket_system_with_credentials() {
    let system = TicketSystem {
        name: "Private".to_string(),
        system_type: "github".to_string(),
        url: "https://private.example.com".to_string(),
        credentials: Some("token123".to_string()),
    };
    
    assert!(system.credentials.is_some());
    assert_eq!(system.credentials.unwrap(), "token123");
}
