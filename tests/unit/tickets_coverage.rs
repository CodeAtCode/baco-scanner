//! Additional test coverage for tickets module
//!
//! This file provides additional coverage for public APIs in src/tickets/
//! that may not be fully covered by inline tests.

use baco::tickets::{TicketReference, TicketSearcher, TicketSystem};

#[test]
fn test_ticket_system_default_values() {
    let system = TicketSystem {
        name: String::new(),
        system_type: String::new(),
        url: String::new(),
        credentials: None,
    };
    assert!(system.name.is_empty());
    assert!(system.system_type.is_empty());
    assert!(system.url.is_empty());
    assert!(system.credentials.is_none());
}

#[test]
fn test_ticket_reference_debug_implementation() {
    let reference = TicketReference {
        ticket_id: "123".to_string(),
        ticket_url: "https://example.com/123".to_string(),
        system: "github".to_string(),
        status: "open".to_string(),
        title: "Test".to_string(),
    };
    let debug_str = format!("{:?}", reference);
    assert!(debug_str.contains("123"));
    assert!(debug_str.contains("github"));
}

#[test]
fn test_ticket_system_clone() {
    let system = TicketSystem {
        name: "Test".to_string(),
        system_type: "github".to_string(),
        url: "https://test.com".to_string(),
        credentials: Some("token".to_string()),
    };
    let cloned = system.clone();
    assert_eq!(system.name, cloned.name);
    assert_eq!(system.system_type, cloned.system_type);
    assert_eq!(system.url, cloned.url);
    assert_eq!(system.credentials, cloned.credentials);
}

#[tokio::test]
async fn test_ticket_searcher_empty_systems() {
    let systems: Vec<TicketSystem> = vec![];
    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test").await.unwrap();
    assert!(results.is_empty());
}

#[tokio::test]
async fn test_search_with_whitespace_query() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];
    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("   ").await.unwrap();
    assert!(results.is_empty());
}

#[tokio::test]
async fn test_search_with_newline_query() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];
    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("\n\t").await.unwrap();
    assert!(results.is_empty());
}

#[test]
fn test_ticket_reference_with_all_states() {
    let states = vec!["open", "closed", "merged", "draft"];
    for state in states {
        let reference = TicketReference {
            ticket_id: "123".to_string(),
            ticket_url: "https://example.com/123".to_string(),
            system: "github".to_string(),
            status: state.to_string(),
            title: "Test".to_string(),
        };
        assert_eq!(reference.status, state);
    }
}

#[test]
fn test_ticket_system_with_various_types() {
    let types = vec!["github", "gitlab", "jira", "bugzilla", "custom"];
    for system_type in types {
        let system = TicketSystem {
            name: format!("{} System", system_type),
            system_type: system_type.to_string(),
            url: format!("https://{}.com", system_type),
            credentials: None,
        };
        assert_eq!(system.system_type, system_type);
    }
}

#[tokio::test]
async fn test_search_with_very_long_query() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];
    let searcher = TicketSearcher::new(systems);
    let long_query = "CVE-2024-1234 ".repeat(100);
    let results = searcher.search_for_finding(&long_query).await.unwrap();
    assert!(results.is_empty());
}

#[tokio::test]
async fn test_search_with_mixed_case_cve() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];
    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("cve-2024-1234").await.unwrap();
    assert!(results.is_empty());
}

#[tokio::test]
async fn test_search_with_github_issue_format() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];
    let searcher = TicketSearcher::new(systems);
    let results = searcher
        .search_for_finding("github.com/owner/repo/issues/123")
        .await
        .unwrap();
    assert!(results.is_empty());
}

#[test]
fn test_ticket_reference_equality() {
    let ref1 = TicketReference {
        ticket_id: "123".to_string(),
        ticket_url: "https://example.com/123".to_string(),
        system: "github".to_string(),
        status: "open".to_string(),
        title: "Test".to_string(),
    };
    let ref2 = ref1.clone();
    assert_eq!(ref1.ticket_id, ref2.ticket_id);
    assert_eq!(ref1.ticket_url, ref2.ticket_url);
}
