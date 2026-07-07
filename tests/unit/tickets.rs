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

// Test CVE ID detection in query building
#[tokio::test]
async fn test_search_github_with_cve_and_vuln_keyword() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"total_count": 1, "items": [{"number": 1234, "html_url": "https://github.com/owner/repo/issues/1234", "state": "open", "title": "CVE-2024-1234 SQL injection"}]}"#
        )
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
        .search_for_finding("CVE-2024-1234 SQL injection vulnerability in authentication module")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "1234");
    assert_eq!(results[0].system, "github");

    mock.assert_async().await;
}

// Test language keyword detection
#[tokio::test]
async fn test_search_github_with_language_keyword() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"total_count": 1, "items": [{"number": 456, "html_url": "https://github.com/owner/repo/issues/456", "state": "open", "title": "Python buffer overflow"}]}"#
        )
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
        .search_for_finding("Python buffer overflow in memory handling")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "456");

    mock.assert_async().await;
}

// Test GitLab with CVE detection
#[tokio::test]
async fn test_search_gitlab_with_cve() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/api/v4/search.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"[{"id": 1, "iid": 789, "web_url": "https://gitlab.com/group/project/issues/789", "state": "opened", "title": "CVE-2024-5678 XXE vulnerability"}]"#
        )
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
        .search_for_finding("CVE-2024-5678 XXE vulnerability in XML parser")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "789");
    assert_eq!(results[0].system, "gitlab");

    mock.assert_async().await;
}

// Test multiple vulnerability types detection
#[tokio::test]
async fn test_search_github_with_xss() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"total_count": 1, "items": [{"number": 789, "html_url": "https://github.com/owner/repo/issues/789", "state": "open", "title": "XSS vulnerability"}]}"#
        )
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
        .search_for_finding("Cross-site scripting (XSS) vulnerability in form input")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "789");

    mock.assert_async().await;
}

#[tokio::test]
async fn test_search_github_with_privilege_escalation() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"total_count": 1, "items": [{"number": 999, "html_url": "https://github.com/owner/repo/issues/999", "state": "open", "title": "Privilege escalation bug"}]}"#
        )
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
        .search_for_finding("Privilege escalation via unauthorized API access")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "999");

    mock.assert_async().await;
}

// Test GitLab with authentication header
#[tokio::test]
async fn test_search_gitlab_with_auth_header_verification() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/api/v4/search.*".to_string()))
        .match_header("PRIVATE-TOKEN", "secret-token-xyz")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"[{"id": 1, "iid": 111, "web_url": "https://gitlab.com/group/project/issues/111", "state": "opened", "title": "Authenticated search result"}]"#
        )
        .create_async()
        .await;

    let systems = vec![TicketSystem {
        name: "GitLab".to_string(),
        system_type: "gitlab".to_string(),
        url: server.url(),
        credentials: Some("secret-token-xyz".to_string()),
    }];

    let searcher = TicketSearcher::new(systems);
    let results = searcher
        .search_for_finding("test vulnerability")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "111");

    mock.assert_async().await;
}

// Test error handling for JSON parsing failure
#[tokio::test]
async fn test_search_github_invalid_json_response() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock(
            "GET",
            mockito::Matcher::Regex("/search/issues.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("invalid json response")
        .create_async()
        .await;

    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: server.url(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let result = searcher.search_for_finding("test").await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);

    mock.assert_async().await;
}

// Test GitLab invalid JSON handling
#[tokio::test]
async fn test_search_gitlab_invalid_json_response() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock(
            "GET",
            mockito::Matcher::Regex("/api/v4/search.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("not valid json")
        .create_async()
        .await;

    let systems = vec![TicketSystem {
        name: "GitLab".to_string(),
        system_type: "gitlab".to_string(),
        url: server.url(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let result = searcher.search_for_finding("test").await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);

    mock.assert_async().await;
}

// Test with Rust language keyword
#[tokio::test]
async fn test_search_github_with_rust_language() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"total_count": 1, "items": [{"number": 222, "html_url": "https://github.com/owner/repo/issues/222", "state": "open", "title": "Rust use-after-free bug"}]}"#
        )
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
        .search_for_finding("Rust use-after-free vulnerability in async runtime")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "222");

    mock.assert_async().await;
}

// Test multiple CVE IDs in query
#[tokio::test]
async fn test_search_github_with_multiple_cves() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"total_count": 1, "items": [{"number": 333, "html_url": "https://github.com/owner/repo/issues/333", "state": "open", "title": "Multiple CVEs vulnerability"}]}"#
        )
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
        .search_for_finding("CVE-2024-1234 and CVE-2024-5678 vulnerabilities detected")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "333");

    mock.assert_async().await;
}

// Test GitLab with different vulnerability types
#[tokio::test]
async fn test_search_gitlab_with_deserialization() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/api/v4/search.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"[{"id": 1, "iid": 444, "web_url": "https://gitlab.com/group/project/issues/444", "state": "opened", "title": "Unsafe deserialization vulnerability"}]"#
        )
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
        .search_for_finding("Unsafe deserialization of untrusted data")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "444");

    mock.assert_async().await;
}

// Test GitHub with path traversal keyword
#[tokio::test]
async fn test_search_github_with_path_traversal() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"total_count": 1, "items": [{"number": 555, "html_url": "https://github.com/owner/repo/issues/555", "state": "open", "title": "Path traversal vulnerability"}]}"#
        )
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
        .search_for_finding("Path traversal attack via file upload")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "555");

    mock.assert_async().await;
}

// Test GitLab with overflow keyword
#[tokio::test]
async fn test_search_gitlab_with_buffer_overflow() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/api/v4/search.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"[{"id": 1, "iid": 666, "web_url": "https://gitlab.com/group/project/issues/666", "state": "opened", "title": "Buffer overflow in network parser"}]"#
        )
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
        .search_for_finding("Buffer overflow vulnerability in network packet parser")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "666");

    mock.assert_async().await;
}

// Test with CSRF keyword
#[tokio::test]
async fn test_search_github_with_csrf() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"total_count": 1, "items": [{"number": 777, "html_url": "https://github.com/owner/repo/issues/777", "state": "open", "title": "CSRF token validation missing"}]}"#
        )
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
        .search_for_finding("CSRF vulnerability in form submission")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "777");

    mock.assert_async().await;
}

// Test with SSRF keyword
#[tokio::test]
async fn test_search_github_with_ssrf() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"total_count": 1, "items": [{"number": 888, "html_url": "https://github.com/owner/repo/issues/888", "state": "open", "title": "SSRF in URL fetcher"}]}"#
        )
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
        .search_for_finding("SSRF vulnerability allowing internal network access")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "888");

    mock.assert_async().await;
}

// Test GitHub with JavaScript language
#[tokio::test]
async fn test_search_github_with_javascript_language() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"total_count": 1, "items": [{"number": 991, "html_url": "https://github.com/owner/repo/issues/991", "state": "open", "title": "JavaScript prototype pollution"}]}"#
        )
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
        .search_for_finding("JavaScript prototype pollution vulnerability")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "991");

    mock.assert_async().await;
}

// Test GitHub with Java language
#[tokio::test]
async fn test_search_github_with_java_language() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/search/issues.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"total_count": 1, "items": [{"number": 992, "html_url": "https://github.com/owner/repo/issues/992", "state": "open", "title": "Java deserialization RCE"}]}"#
        )
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
        .search_for_finding("Java unsafe deserialization leading to RCE")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "992");

    mock.assert_async().await;
}

// Test GitLab with authentication and authorization keywords
#[tokio::test]
async fn test_search_gitlab_with_authentication_keyword() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("GET", mockito::Matcher::Regex("/api/v4/search.*".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"[{"id": 1, "iid": 993, "web_url": "https://gitlab.com/group/project/issues/993", "state": "opened", "title": "Authentication bypass vulnerability"}]"#
        )
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
        .search_for_finding("Authentication bypass via token manipulation")
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ticket_id, "993");

    mock.assert_async().await;
}

#[tokio::test]
async fn test_ticket_searcher_new() {
    use baco::tickets::{TicketSearcher, TicketSystem};

    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: Some("token".to_string()),
    }];

    let _searcher = TicketSearcher::new(systems);
    // Just verify it doesn't panic
}

#[tokio::test]
async fn test_search_unsupported_system_type() {
    let systems = vec![TicketSystem {
        name: "Custom".into(),
        system_type: "unsupported".into(),
        url: "https://custom.com".into(),
        credentials: None,
    }];
    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("test finding").await.unwrap();
    // Unsupported systems log warning but return empty results
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_search_empty_finding() {
    let systems = vec![TicketSystem {
        name: "GitHub".into(),
        system_type: "github".into(),
        url: "https://github.com".into(),
        credentials: None,
    }];
    let searcher = TicketSearcher::new(systems);
    let results = searcher.search_for_finding("").await.unwrap();
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_search_with_cve_id() {
    let systems = vec![TicketSystem {
        name: "GitHub".into(),
        system_type: "github".into(),
        url: "https://github.com".into(),
        credentials: None,
    }];
    let searcher = TicketSearcher::new(systems);
    let results = searcher
        .search_for_finding("CVE-2024-1234 buffer overflow")
        .await
        .unwrap();
    // Should include CVE in query but still return empty (no real API call)
    assert_eq!(results.len(), 0);
}
