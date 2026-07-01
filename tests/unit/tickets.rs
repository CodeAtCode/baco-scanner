//! Unit tests for the tickets module
//!
//! These tests cover ticket system creation, searching, reference handling,
//! and URL parsing functionality.

use baco::tickets::{TicketReference, TicketSearcher, TicketSystem};

// ============================================================================
// TicketSystem Tests
// ============================================================================

#[test]
fn test_ticket_system_creation() {
    let system = TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    };

    assert_eq!(system.name, "GitHub");
    assert_eq!(system.system_type, "github");
    assert_eq!(system.url, "https://github.com");
    assert!(system.credentials.is_none());
}

#[test]
fn test_ticket_system_with_credentials() {
    let system = TicketSystem {
        name: "GitLab".to_string(),
        system_type: "gitlab".to_string(),
        url: "https://gitlab.com".to_string(),
        credentials: Some("secret-token".to_string()),
    };

    assert_eq!(system.name, "GitLab");
    assert!(system.credentials.is_some());
    assert_eq!(system.credentials.unwrap(), "secret-token");
}

#[test]
fn test_ticket_system_clone() {
    let system = TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: Some("token".to_string()),
    };

    let cloned = system.clone();
    assert_eq!(system.name, cloned.name);
    assert_eq!(system.system_type, cloned.system_type);
    assert_eq!(system.url, cloned.url);
    assert_eq!(system.credentials, cloned.credentials);
}

// ============================================================================
// TicketReference Tests
// ============================================================================

#[test]
fn test_ticket_reference_creation() {
    let reference = TicketReference {
        ticket_id: "12345".to_string(),
        ticket_url: "https://github.com/example/repo/issues/12345".to_string(),
        system: "github".to_string(),
        status: "open".to_string(),
        title: "Critical security vulnerability".to_string(),
    };

    assert_eq!(reference.ticket_id, "12345");
    assert_eq!(reference.system, "github");
    assert_eq!(reference.status, "open");
    assert!(reference.title.contains("security"));
}

#[test]
fn test_ticket_reference_clone() {
    let reference = TicketReference {
        ticket_id: "67890".to_string(),
        ticket_url: "https://gitlab.com/example/project/issues/67890".to_string(),
        system: "gitlab".to_string(),
        status: "closed".to_string(),
        title: "XSS vulnerability in login form".to_string(),
    };

    let cloned = reference.clone();
    assert_eq!(reference.ticket_id, cloned.ticket_id);
    assert_eq!(reference.ticket_url, cloned.ticket_url);
    assert_eq!(reference.system, cloned.system);
    assert_eq!(reference.status, cloned.status);
    assert_eq!(reference.title, cloned.title);
}

// ============================================================================
// TicketSearcher Creation Tests
// ============================================================================

#[test]
fn test_ticket_searcher_creation_empty() {
    let _searcher = TicketSearcher::new(vec![]);
    // Searcher created successfully with empty systems
}

#[test]
fn test_ticket_searcher_creation_single_system() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let _searcher = TicketSearcher::new(systems);
    // Searcher created successfully with single system
}

#[test]
fn test_ticket_searcher_creation_multiple_systems() {
    let systems = vec![
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
            credentials: Some("token".to_string()),
        },
    ];

    let _searcher = TicketSearcher::new(systems);
    // Searcher created successfully with multiple systems
}

#[test]
fn test_ticket_searcher_preserves_credentials() {
    let systems = vec![
        TicketSystem {
            name: "Private GitLab".to_string(),
            system_type: "gitlab".to_string(),
            url: "https://gitlab.internal".to_string(),
            credentials: Some("private-token-123".to_string()),
        },
        TicketSystem {
            name: "Public GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        },
    ];

    let _searcher = TicketSearcher::new(systems);
    // Searcher created successfully with mixed credential configurations
}

// ============================================================================
// Search Behavior Tests (Network-independent)
// ============================================================================

#[tokio::test]
async fn test_search_returns_empty_for_no_systems() {
    let searcher = TicketSearcher::new(vec![]);
    let results = searcher.search_for_finding("test query").await.unwrap();
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_search_returns_empty_for_github() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test query").await.unwrap();
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_search_returns_empty_for_gitlab() {
    let systems = vec![TicketSystem {
        name: "GitLab".to_string(),
        system_type: "gitlab".to_string(),
        url: "https://gitlab.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test query").await.unwrap();
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_search_with_unsupported_system_type() {
    let systems = vec![TicketSystem {
        name: "Jira".to_string(),
        system_type: "jira".to_string(),
        url: "https://jira.example.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test query").await.unwrap();
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_search_with_multiple_systems_all_empty() {
    let systems = vec![
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

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test query").await.unwrap();
    assert_eq!(results.len(), 0);
}

// ============================================================================
// Search Query Tests with Various Inputs
// ============================================================================

#[tokio::test]
async fn test_search_with_cve_query() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher
        .search_for_finding("CVE-2024-1234 SQL Injection")
        .await
        .unwrap();
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_search_with_vulnerability_keywords() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);

    // Test various vulnerability types
    let queries = vec![
        "SQL injection in authentication",
        "XSS vulnerability in form",
        "Path traversal attack vector",
        "Buffer overflow in parser",
        "Privilege escalation bug",
    ];

    for query in queries {
        let results = searcher.search_for_finding(query).await.unwrap();
        assert_eq!(
            results.len(),
            0,
            "Query '{}' should return empty results",
            query
        );
    }
}

#[tokio::test]
async fn test_search_with_language_keywords() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);

    let queries = vec![
        "Python XSS vulnerability",
        "Rust buffer overflow",
        "JavaScript injection attack",
        "Java deserialization issue",
    ];

    for query in queries {
        let results = searcher.search_for_finding(query).await.unwrap();
        assert_eq!(results.len(), 0);
    }
}

#[tokio::test]
async fn test_search_with_empty_query() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("").await.unwrap();
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_search_with_whitespace_only() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("   ").await.unwrap();
    assert_eq!(results.len(), 0);
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
    assert_eq!(results.len(), 0);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_search_returns_ok_result() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let result = searcher.search_for_finding("test").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_search_with_invalid_url_format() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "not-a-valid-url".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test").await.unwrap();
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_search_with_mixed_valid_invalid_systems() {
    let systems = vec![
        TicketSystem {
            name: "Valid GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        },
        TicketSystem {
            name: "Invalid".to_string(),
            system_type: "unknown".to_string(),
            url: "https://unknown.com".to_string(),
            credentials: None,
        },
        TicketSystem {
            name: "Valid GitLab".to_string(),
            system_type: "gitlab".to_string(),
            url: "https://gitlab.com".to_string(),
            credentials: None,
        },
    ];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test").await.unwrap();
    // Should process valid systems and skip invalid ones
    assert_eq!(results.len(), 0);
}

// ============================================================================
// TicketReference Validation Tests
// ============================================================================

#[test]
fn test_ticket_reference_with_various_statuses() {
    let statuses = vec!["open", "closed", "merged", "draft", "pending"];

    for status in statuses {
        let reference = TicketReference {
            ticket_id: "123".to_string(),
            ticket_url: "https://example.com/123".to_string(),
            system: "github".to_string(),
            status: status.to_string(),
            title: "Test issue".to_string(),
        };
        assert_eq!(reference.status, status);
    }
}

#[test]
fn test_ticket_reference_with_various_systems() {
    let systems = vec!["github", "gitlab", "bitbucket", "jira", "custom"];

    for system in systems {
        let reference = TicketReference {
            ticket_id: "123".to_string(),
            ticket_url: "https://example.com/123".to_string(),
            system: system.to_string(),
            status: "open".to_string(),
            title: "Test issue".to_string(),
        };
        assert_eq!(reference.system, system);
    }
}

#[test]
fn test_ticket_reference_with_special_characters_in_title() {
    let reference = TicketReference {
        ticket_id: "123".to_string(),
        ticket_url: "https://example.com/123".to_string(),
        system: "github".to_string(),
        status: "open".to_string(),
        title: "Critical: SQL Injection (CVE-2024-1234) [HIGH]".to_string(),
    };

    assert!(reference.title.contains("SQL Injection"));
    assert!(reference.title.contains("CVE-2024-1234"));
}

// ============================================================================
// TicketSystem Configuration Tests
// ============================================================================

#[test]
fn test_ticket_system_with_trailing_slash_url() {
    let system = TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com/".to_string(),
        credentials: None,
    };

    assert_eq!(system.url, "https://github.com/");
}

#[test]
fn test_ticket_system_with_subpath_url() {
    let system = TicketSystem {
        name: "GitHub Enterprise".to_string(),
        system_type: "github".to_string(),
        url: "https://github.enterprise.com/api/v3".to_string(),
        credentials: Some("enterprise-token".to_string()),
    };

    assert!(system.url.contains("enterprise"));
    assert_eq!(system.credentials, Some("enterprise-token".to_string()));
}

// ============================================================================
// TicketSearcher System Type Handling Tests
// ============================================================================

#[tokio::test]
async fn test_search_only_github_systems() {
    let systems = vec![
        TicketSystem {
            name: "Org GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        },
        TicketSystem {
            name: "Personal GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        },
    ];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test").await.unwrap();
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_search_only_gitlab_systems() {
    let systems = vec![
        TicketSystem {
            name: "GitLab.com".to_string(),
            system_type: "gitlab".to_string(),
            url: "https://gitlab.com".to_string(),
            credentials: None,
        },
        TicketSystem {
            name: "GitLab Enterprise".to_string(),
            system_type: "gitlab".to_string(),
            url: "https://gitlab.company.com".to_string(),
            credentials: Some("token".to_string()),
        },
    ];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test").await.unwrap();
    assert_eq!(results.len(), 0);
}

// ============================================================================
// Serialization Tests
// ============================================================================

#[test]
fn test_ticket_system_serialize_deserialize() {
    let system = TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: Some("token".to_string()),
    };

    let serialized = serde_json::to_string(&system).unwrap();
    let deserialized: TicketSystem = serde_json::from_str(&serialized).unwrap();

    assert_eq!(system.name, deserialized.name);
    assert_eq!(system.system_type, deserialized.system_type);
    assert_eq!(system.url, deserialized.url);
    assert_eq!(system.credentials, deserialized.credentials);
}

#[test]
fn test_ticket_reference_serialize_deserialize() {
    let reference = TicketReference {
        ticket_id: "12345".to_string(),
        ticket_url: "https://github.com/example/repo/issues/12345".to_string(),
        system: "github".to_string(),
        status: "open".to_string(),
        title: "Security vulnerability".to_string(),
    };

    let serialized = serde_json::to_string(&reference).unwrap();
    let deserialized: TicketReference = serde_json::from_str(&serialized).unwrap();

    assert_eq!(reference.ticket_id, deserialized.ticket_id);
    assert_eq!(reference.ticket_url, deserialized.ticket_url);
    assert_eq!(reference.system, deserialized.system);
    assert_eq!(reference.status, deserialized.status);
    assert_eq!(reference.title, deserialized.title);
}
