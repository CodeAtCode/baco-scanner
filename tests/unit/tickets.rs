//! Unit tests for src/tickets.rs
//!
//! Covers:
//! - TicketSystem and TicketSearcher initialization
//! - Multiple system configurations  
//! - Credential handling
//! - HTTP mocking with mockito for GitHub and GitLab API responses

use baco::tickets::*;
use mockito::Server;

#[test]
fn test_ticket_searcher_new_empty_systems() {
    let systems = vec![];
    let _searcher = TicketSearcher::new(systems);

    // Just test that creation doesn't panic
}

#[test]
fn test_ticket_searcher_new_with_systems() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];
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
    let systems = vec![TicketSystem {
        name: "GitLab".to_string(),
        system_type: "gitlab".to_string(),
        url: "https://gitlab.com".to_string(),
        credentials: None,
    }];
    let _searcher = TicketSearcher::new(systems);

    // Just test that creation doesn't panic
}

#[test]
fn test_ticket_searcher_with_unknown_system_type() {
    let systems = vec![TicketSystem {
        name: "Unknown".to_string(),
        system_type: "jira".to_string(),
        url: "https://jira.example.com".to_string(),
        credentials: None,
    }];
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

// Mockito-based tests for HTTP response handling
#[tokio::test]
async fn test_search_github_successful_response() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"total_count": 1, "items": [{"number": 123, "html_url": "https://github.com/owner/repo/issues/123", "state": "open", "title": "Test issue"}]}"#)
        .create_async()
        .await;

    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: server.url(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher
        .search_for_finding("test vulnerability")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "123");
    assert_eq!(results[0].system, "github");
    assert_eq!(results[0].title, "Test issue");

    mock.assert_async().await;
}

#[tokio::test]
async fn test_search_github_empty_response() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock(
            "GET",
            mockito::Matcher::Regex("/search/issues.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"total_count": 0, "items": []}"#)
        .create_async()
        .await;

    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: server.url(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test").await.unwrap();

    assert_eq!(results.len(), 0);

    mock.assert_async().await;
}

#[tokio::test]
async fn test_search_github_error_response() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock(
            "GET",
            mockito::Matcher::Regex("/search/issues.*".to_string()),
        )
        .with_status(401)
        .with_body("Unauthorized")
        .create_async()
        .await;

    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: server.url(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test").await.unwrap();

    // Error responses return empty results (logged as warning)
    assert_eq!(results.len(), 0);

    mock.assert_async().await;
}

#[tokio::test]
async fn test_search_gitlab_successful_response() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/api/v4/search.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"[{"id": 1, "iid": 456, "web_url": "https://gitlab.com/group/project/issues/456", "state": "opened", "title": "GitLab issue"}]"#)
        .create_async()
        .await;

    let systems = vec![TicketSystem {
        name: "GitLab".to_string(),
        system_type: "gitlab".to_string(),
        url: server.url(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher
        .search_for_finding("test vulnerability")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "456");
    assert_eq!(results[0].system, "gitlab");

    mock.assert_async().await;
}

#[tokio::test]
async fn test_search_gitlab_empty_response() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock(
            "GET",
            mockito::Matcher::Regex("/api/v4/search.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("[]")
        .create_async()
        .await;

    let systems = vec![TicketSystem {
        name: "GitLab".to_string(),
        system_type: "gitlab".to_string(),
        url: server.url(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test").await.unwrap();

    assert_eq!(results.len(), 0);

    mock.assert_async().await;
}

#[tokio::test]
async fn test_search_gitlab_with_credentials() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/api/v4/search.*".to_string()))
        .match_header("PRIVATE-TOKEN", "test-token-123")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"[{"id": 1, "iid": 789, "web_url": "https://gitlab.com/group/project/issues/789", "state": "opened", "title": "Authenticated issue"}]"#)
        .create_async()
        .await;

    let systems = vec![TicketSystem {
        name: "GitLab".to_string(),
        system_type: "gitlab".to_string(),
        url: server.url(),
        credentials: Some("test-token-123".to_string()),
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test").await.unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "789");

    mock.assert_async().await;
}

#[tokio::test]
async fn test_search_gitlab_error_response() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock(
            "GET",
            mockito::Matcher::Regex("/api/v4/search.*".to_string()),
        )
        .with_status(403)
        .with_body("Forbidden")
        .create_async()
        .await;

    let systems = vec![TicketSystem {
        name: "GitLab".to_string(),
        system_type: "gitlab".to_string(),
        url: server.url(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test").await.unwrap();

    assert_eq!(results.len(), 0);

    mock.assert_async().await;
}

#[tokio::test]
async fn test_search_with_both_github_and_gitlab() {
    let mut github_server = Server::new_async().await;
    let mut gitlab_server = Server::new_async().await;

    let github_mock = github_server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"total_count": 1, "items": [{"number": 1, "html_url": "https://github.com/owner/repo/issues/1", "state": "open", "title": "GitHub issue"}]}"#)
        .create_async()
        .await;

    let gitlab_mock = gitlab_server
        .mock("GET", mockito::Matcher::Regex("/api/v4/search.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"[{"id": 1, "iid": 2, "web_url": "https://gitlab.com/group/project/issues/2", "state": "opened", "title": "GitLab issue"}]"#)
        .create_async()
        .await;

    let systems = vec![
        TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: github_server.url(),
            credentials: None,
        },
        TicketSystem {
            name: "GitLab".to_string(),
            system_type: "gitlab".to_string(),
            url: gitlab_server.url(),
            credentials: None,
        },
    ];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test").await.unwrap();

    // Should get results from both systems
    assert_eq!(results.len(), 2);

    github_mock.assert_async().await;
    gitlab_mock.assert_async().await;
}

#[tokio::test]
async fn test_search_with_mixed_success_failure() {
    let mut github_server = Server::new_async().await;
    let mut gitlab_server = Server::new_async().await;

    let github_mock = github_server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"total_count": 1, "items": [{"number": 1, "html_url": "https://github.com/owner/repo/issues/1", "state": "open", "title": "GitHub issue"}]}"#)
        .create_async()
        .await;

    let gitlab_mock = gitlab_server
        .mock(
            "GET",
            mockito::Matcher::Regex("/api/v4/search.*".to_string()),
        )
        .with_status(500)
        .with_body("Internal Server Error")
        .create_async()
        .await;

    let systems = vec![
        TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: github_server.url(),
            credentials: None,
        },
        TicketSystem {
            name: "GitLab".to_string(),
            system_type: "gitlab".to_string(),
            url: gitlab_server.url(),
            credentials: None,
        },
    ];

    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test").await.unwrap();

    // Should get only GitHub result (GitLab failed)
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].system, "github");

    github_mock.assert_async().await;
    gitlab_mock.assert_async().await;
}

#[tokio::test]
async fn test_search_github_with_cve_id() {
    let mut server = Server::new_async().await;

    // Mock should match CVE query with regex for query params
    let mock = server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"total_count": 1, "items": [{"number": 2024, "html_url": "https://github.com/owner/repo/issues/2024", "state": "open", "title": "CVE-2024-1234 vulnerability"}]}"#)
        .create_async()
        .await;

    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: server.url(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher
        .search_for_finding("CVE-2024-1234 SQL injection")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "2024");

    mock.assert_async().await;
}

#[tokio::test]
async fn test_ticket_reference_clone_and_debug() {
    let reference = TicketReference {
        ticket_id: "123".to_string(),
        ticket_url: "https://github.com/owner/repo/issues/123".to_string(),
        system: "github".to_string(),
        status: "open".to_string(),
        title: "Test issue".to_string(),
    };

    let cloned = reference.clone();
    assert_eq!(reference.ticket_id, cloned.ticket_id);
    assert_eq!(reference.ticket_url, cloned.ticket_url);

    let debug_output = format!("{:?}", reference);
    assert!(debug_output.contains("123"));
    assert!(debug_output.contains("github"));
}

#[test]
fn test_ticket_searcher_new() {
    use baco::tickets::{TicketSearcher, TicketSystem};

    let systems = vec![
        TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: Some("token".to_string()),
        },
    ];

    let _searcher = TicketSearcher::new(systems);
    // Just verify it doesn't panic
}
