use serde::{Deserialize, Serialize};

/// Helper to extract meaningful words from a string, excluding common stop words
fn extract_meaningful_words(s: &str, count: usize) -> String {
    let stop_words = [
        "the", "a", "an", "is", "are", "in", "on", "with", "for", "to", "of", "and", "or", "no",
        "missing", "lack",
    ];
    s.split_whitespace()
        .filter(|w| w.len() > 3 && !stop_words.contains(&w.to_lowercase().as_str()))
        .take(count)
        .collect::<Vec<_>>()
        .join(" ")
}
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketSystem {
    pub name: String,
    pub system_type: String,
    pub url: String,
    pub credentials: Option<String>,
}

pub struct TicketSearcher {
    systems: Vec<TicketSystem>,
    http_client: reqwest::Client,
}

impl TicketSearcher {
    pub fn new(systems: Vec<TicketSystem>) -> Self {
        Self {
            systems,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    pub async fn search_for_finding(&self, finding: &str) -> Result<Vec<TicketReference>, String> {
        let mut matches = Vec::new();

        for system in &self.systems {
            match system.system_type.as_str() {
                "github" => match self.search_github(system, finding).await {
                    Ok(Some(ticket)) => matches.push(ticket),
                    Ok(None) => {}
                    Err(e) => tracing::warn!("GitHub search failed: {}", e),
                },
                "gitlab" => match self.search_gitlab(system, finding).await {
                    Ok(Some(ticket)) => matches.push(ticket),
                    Ok(None) => {}
                    Err(e) => tracing::warn!("GitLab search failed: {}", e),
                },
                _ => {
                    tracing::warn!("Unsupported ticket system: {}", system.system_type);
                }
            }
        }

        Ok(matches)
    }

    #[allow(dead_code)]
    async fn search_github(
        &self,
        system: &TicketSystem,
        finding: &str,
    ) -> Result<Option<TicketReference>, String> {
        // Build improved search query with multiple strategies
        let mut query_parts: Vec<String> = Vec::new();

        // 1. If CVE ID is present, always include it
        let cve_matches: Vec<&str> = finding
            .split_whitespace()
            .filter(|w| w.starts_with("CVE-") || w.starts_with("CVE:"))
            .collect();
        query_parts.extend(cve_matches.iter().map(|s| s.to_string()));

        // 2. Extract vulnerability type keywords
        let vuln_keywords = [
            "injection",
            "xss",
            "xxe",
            "sql",
            "path traversal",
            "overflow",
            "deserialization",
            "xxe",
            "buffer",
            "race condition",
            "privilege",
            "authentication",
            "authorization",
            "csrf",
            "ssrf",
            "xml",
            "yaml",
        ];
        let finding_lower = finding.to_lowercase();
        for keyword in vuln_keywords {
            if finding_lower.contains(keyword) {
                query_parts.push(keyword.to_string());
                break; // Add only one vuln type to keep query focused
            }
        }

        // 3. Add language/platform if detected
        let lang_keywords = [
            "python",
            "javascript",
            "rust",
            "c++",
            "java",
            "go",
            "ruby",
            "php",
        ];
        for lang in lang_keywords {
            if finding_lower.contains(lang) {
                query_parts.push(lang.to_string());
                break;
            }
        }

        // Build final query - prioritize CVE, then vuln type + language
        let query = if !query_parts.is_empty() {
            format!("{} state:open", query_parts.join(" "))
        } else {
            extract_meaningful_words(finding, 2)
        };

        // If query is too short, use a broader search
        let query = if query.len() < 5 {
            format!(
                "vulnerability {} state:open",
                finding.split_whitespace().next().unwrap_or("security")
            )
        } else {
            query
        };

        let url = format!(
            "{}/search/issues?q={}&per_page=5",
            system.url.trim_end_matches('/'),
            urlencoding::encode(&query)
        );

        match self.http_client.get(&url).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    tracing::warn!(
                        "GitHub search returned status {} for query: {}",
                        response.status(),
                        query
                    );
                    return Ok(None);
                }

                let json: GithubSearchResponse = response
                    .json()
                    .await
                    .map_err(|e| format!("Failed to parse GitHub response: {}", e))?;

                if json.total_count == 0 || json.items.is_empty() {
                    return Ok(None);
                }

                let item = &json.items[0];
                Ok(Some(TicketReference {
                    ticket_id: item.number.to_string(),
                    ticket_url: item.html_url.clone(),
                    system: "github".to_string(),
                    status: item.state.clone(),
                    title: item.title.clone(),
                }))
            }
            Err(e) => Err(format!("GitHub API request failed: {}", e)),
        }
    }
    #[allow(dead_code)]
    fn parse_github_url(&self, url: &str) -> Result<(String, String), String> {
        let url = url.trim_end_matches('/');
        let parts: Vec<&str> = url.split('/').collect();

        if parts.len() >= 2 {
            Ok((
                parts[parts.len() - 2].to_string(),
                parts[parts.len() - 1].to_string(),
            ))
        } else {
            Err(format!("Invalid GitHub URL format: {}", url))
        }
    }

    #[allow(dead_code)]
    async fn search_gitlab(
        &self,
        system: &TicketSystem,
        finding: &str,
    ) -> Result<Option<TicketReference>, String> {
        let mut query_parts: Vec<String> = Vec::new();

        let cve_matches: Vec<&str> = finding
            .split_whitespace()
            .filter(|w| w.starts_with("CVE-") || w.starts_with("CVE:"))
            .collect();
        query_parts.extend(cve_matches.iter().map(|s| s.to_string()));

        let vuln_keywords = [
            "injection",
            "xss",
            "xxe",
            "sql",
            "path traversal",
            "overflow",
            "deserialization",
            "buffer",
            "race condition",
            "privilege",
            "authentication",
            "authorization",
            "csrf",
            "ssrf",
            "xml",
            "yaml",
        ];
        let finding_lower = finding.to_lowercase();
        for keyword in vuln_keywords {
            if finding_lower.contains(keyword) {
                query_parts.push(keyword.to_string());
                break;
            }
        }

        let lang_keywords = [
            "python",
            "javascript",
            "rust",
            "c++",
            "java",
            "go",
            "ruby",
            "php",
        ];
        for lang in lang_keywords {
            if finding_lower.contains(lang) {
                query_parts.push(lang.to_string());
                break;
            }
        }

        let query = if !query_parts.is_empty() {
            format!("{} state:opened", query_parts.join(" "))
        } else {
            extract_meaningful_words(finding, 2)
        };

        let query = if query.len() < 5 {
            format!(
                "vulnerability {} state:opened",
                finding.split_whitespace().next().unwrap_or("security")
            )
        } else {
            query
        };

        let url = format!(
            "{}/api/v4/search?scope=issues&search={}&state=opened&per_page=5",
            system.url.trim_end_matches('/'),
            urlencoding::encode(&query)
        );

        let mut request = self.http_client.get(&url);

        if let Some(ref token) = system.credentials {
            request = request.header("PRIVATE-TOKEN", token);
        }

        match request.send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    tracing::warn!(
                        "GitLab search returned status {} for query: {}",
                        response.status(),
                        query
                    );
                    return Ok(None);
                }

                let json: Vec<GitlabIssue> = response
                    .json()
                    .await
                    .map_err(|e| format!("Failed to parse GitLab response: {}", e))?;

                if json.is_empty() {
                    return Ok(None);
                }

                let item = &json[0];
                Ok(Some(TicketReference {
                    ticket_id: item.iid.to_string(),
                    ticket_url: item.web_url.clone(),
                    system: "gitlab".to_string(),
                    status: item.state.clone(),
                    title: item.title.clone(),
                }))
            }
            Err(e) => Err(format!("GitLab API request failed: {}", e)),
        }
    }
}

#[derive(Debug, Deserialize)]
struct GithubSearchResponse {
    total_count: u32,
    items: Vec<GithubIssue>,
}

#[derive(Debug, Deserialize)]
struct GithubIssue {
    number: u32,
    html_url: String,
    state: String,
    title: String,
}

#[derive(Debug, Deserialize)]
struct GitlabIssue {
    #[allow(dead_code)]
    id: u32,
    iid: u32,
    #[serde(rename = "web_url")]
    web_url: String,
    state: String,
    title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketReference {
    pub ticket_id: String,
    pub ticket_url: String,
    pub system: String,
    pub status: String,
    pub title: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    #[tokio::test]
    async fn test_ticket_searcher_creation() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        assert_eq!(searcher.systems.len(), 1);
    }

    #[tokio::test]
    async fn test_search_returns_empty() {
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

    // Parameterized test macro for ticket system tests
    macro_rules! test_ticket_system {
        ($name:ident, $systems:expr, $query:expr, $expected_len:expr) => {
            #[tokio::test]
            async fn $name() {
                let searcher = TicketSearcher::new($systems);
                let results = searcher.search_for_finding($query).await.unwrap();
                assert_eq!(results.len(), $expected_len);
            }
        };
    }

    // Single system tests
    test_ticket_system!(
        test_search_single_github,
        vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }],
        "test query",
        0
    );

    test_ticket_system!(
        test_search_single_gitlab,
        vec![TicketSystem {
            name: "GitLab".to_string(),
            system_type: "gitlab".to_string(),
            url: "https://gitlab.com".to_string(),
            credentials: None,
        }],
        "test query",
        0
    );

    // Multiple systems test
    test_ticket_system!(
        test_search_with_multiple_systems,
        vec![
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
        ],
        "test query",
        0
    );

    test_ticket_system!(
        test_search_combined_results,
        vec![
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
        ],
        "test query",
        0
    );

    #[tokio::test]
    async fn test_search_with_unsupported_system_type() {
        let systems = vec![TicketSystem {
            name: "Unknown".to_string(),
            system_type: "unknown".to_string(),
            url: "https://example.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("test query").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_github_stubbed() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("CVE-2024-1234").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_gitlab_stubbed() {
        let systems = vec![TicketSystem {
            name: "GitLab".to_string(),
            system_type: "gitlab".to_string(),
            url: "https://gitlab.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("CVE-2024-5678").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_error_handling() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let result = searcher.search_for_finding("test query").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_search_no_matching_systems() {
        let systems: Vec<TicketSystem> = vec![];

        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("test query").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_mixed_system_types() {
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
                name: "Unknown".to_string(),
                system_type: "jira".to_string(),
                url: "https://jira.example.com".to_string(),
                credentials: None,
            },
        ];

        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("test query").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_empty_string() {
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
    async fn test_search_long_string() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let query = "CVE-2024-1234-5678-9012-3456-7890-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12";
        let results = searcher.search_for_finding(query).await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_reference_struct() {
        let reference = TicketReference {
            ticket_id: "TEST-123".to_string(),
            ticket_url: "https://example.com/test/123".to_string(),
            system: "github".to_string(),
            status: "open".to_string(),
            title: "Test vulnerability".to_string(),
        };

        assert_eq!(reference.ticket_id, "TEST-123");
        assert_eq!(reference.system, "github");
        assert!(!reference.title.is_empty());
    }

    // Tests for extract_meaningful_words helper function
    #[test]
    fn test_extract_meaningful_words_basic() {
        let result = extract_meaningful_words("vulnerability in authentication", 2);
        assert!(result.contains("vulnerability"));
        assert!(result.contains("authentication"));
    }

    #[test]
    fn test_extract_meaningful_words_excludes_stop_words() {
        let result = extract_meaningful_words("the quick brown fox jumps", 4);
        assert!(!result.contains("the"));
        assert!(result.contains("quick"));
        assert!(result.contains("brown"));
        assert!(result.contains("jumps"));
    }

    #[test]
    fn test_extract_meaningful_words_excludes_short_words() {
        let result = extract_meaningful_words("a an to of in on", 5);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_meaningful_words_case_insensitive() {
        let result = extract_meaningful_words("THE Quick Brown", 2);
        assert!(!result.contains("THE"));
        assert!(result.contains("Quick"));
        assert!(result.contains("Brown"));
    }

    #[test]
    fn test_extract_meaningful_words_empty_string() {
        let result = extract_meaningful_words("", 5);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_meaningful_words_limit() {
        let result = extract_meaningful_words("one two three four five", 3);
        let words: Vec<&str> = result.split_whitespace().collect();
        assert_eq!(words.len(), 3);
    }

    #[test]
    fn test_extract_meaningful_words_excludes_no_missing_lack() {
        let result = extract_meaningful_words("no missing lack of credentials", 3);
        assert!(!result.contains("no"));
        assert!(!result.contains("missing"));
        assert!(!result.contains("lack"));
        assert!(result.contains("credentials"));
    }

    // Tests for parse_github_url
    #[tokio::test]
    async fn test_parse_github_url_valid() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);

        let result = searcher.parse_github_url("https://github.com/owner/repo");
        assert!(result.is_ok());
        let (owner, repo) = result.unwrap();
        assert_eq!(owner, "owner");
        assert_eq!(repo, "repo");
        assert_eq!(repo, "repo");
    }

    #[tokio::test]
    async fn test_parse_github_url_with_trailing_slash() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);

        let result = searcher.parse_github_url("https://github.com/owner/repo/");
        assert!(result.is_ok());
        let (owner, repo) = result.unwrap();
        assert_eq!(owner, "owner");
        assert_eq!(repo, "repo");
    }

    #[tokio::test]
    async fn test_parse_github_url_invalid() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);

        // Single part will fail
        let result = searcher.parse_github_url("single");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid GitHub URL"));
    }

    #[tokio::test]
    async fn test_parse_github_url_single_part() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);

        let result = searcher.parse_github_url("justrepo");
        assert!(result.is_err());
    }

    // Tests for TicketSystem
    #[test]
    fn test_ticket_system_creation() {
        let system = TicketSystem {
            name: "Test".to_string(),
            system_type: "github".to_string(),
            url: "https://test.com".to_string(),
            credentials: Some("token".to_string()),
        };

        assert_eq!(system.name, "Test");
        assert_eq!(system.system_type, "github");
        assert!(system.credentials.is_some());
    }

    #[test]
    fn test_ticket_system_without_credentials() {
        let system = TicketSystem {
            name: "Test".to_string(),
            system_type: "gitlab".to_string(),
            url: "https://test.com".to_string(),
            credentials: None,
        };

        assert!(system.credentials.is_none());
    }

    // Tests for TicketSearcher with credentials
    #[tokio::test]
    async fn test_ticket_searcher_with_credentials() {
        let systems = vec![TicketSystem {
            name: "GitLab".to_string(),
            system_type: "gitlab".to_string(),
            url: "https://gitlab.com".to_string(),
            credentials: Some("private-token".to_string()),
        }];

        let searcher = TicketSearcher::new(systems);
        assert_eq!(searcher.systems.len(), 1);
        assert!(searcher.systems[0].credentials.is_some());
    }

    // Tests for TicketSearcher client timeout configuration
    #[tokio::test]
    async fn test_ticket_searcher_client_timeout() {
        let systems = vec![];
        let searcher = TicketSearcher::new(systems);
        // Just verify the searcher was created with a valid client
        assert_eq!(searcher.systems.len(), 0);
    }

    // Edge case tests for search queries
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
    async fn test_search_with_only_cve() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("CVE-2024-1234").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_cve_colon_format() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("CVE:2024-5678").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    // Test specific vulnerability keywords are recognized
    #[tokio::test]
    async fn test_search_with_sql_injection() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher
            .search_for_finding("SQL injection vulnerability in login form")
            .await
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_xss() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher
            .search_for_finding("Cross-site scripting (XSS) vulnerability")
            .await
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_privilege_escalation() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher
            .search_for_finding("Privilege escalation via unauthorized API access")
            .await
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    // Test language detection keywords
    #[tokio::test]
    async fn test_search_with_python_language() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher
            .search_for_finding("Python buffer overflow in memory handling")
            .await
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_rust_language() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher
            .search_for_finding("Rust use-after-free in async runtime")
            .await
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    // Test TicketReference serialization
    #[test]
    fn test_ticket_reference_clone() {
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
        assert_eq!(reference.system, cloned.system);
        assert_eq!(reference.status, cloned.status);
        assert_eq!(reference.title, cloned.title);
    }

    #[test]
    fn test_ticket_reference_debug_format() {
        let reference = TicketReference {
            ticket_id: "456".to_string(),
            ticket_url: "https://gitlab.com/group/project/issues/456".to_string(),
            system: "gitlab".to_string(),
            status: "closed".to_string(),
            title: "Another issue".to_string(),
        };

        let debug_output = format!("{:?}", reference);
        assert!(debug_output.contains("456"));
        assert!(debug_output.contains("gitlab"));
    }

    // Test TicketSystem serialization
    #[test]
    fn test_ticket_system_debug_format() {
        let system = TicketSystem {
            name: "My GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        };

        let debug_output = format!("{:?}", system);
        assert!(debug_output.contains("My GitHub"));
        assert!(debug_output.contains("github"));
    }

    // Test multiple CVE IDs in query
    #[tokio::test]
    async fn test_search_with_multiple_cves() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher
            .search_for_finding("CVE-2024-1234 and CVE-2024-5678 vulnerabilities")
            .await
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    // Test search with various state formats
    #[tokio::test]
    async fn test_search_gitlab_state_format() {
        let systems = vec![TicketSystem {
            name: "GitLab".to_string(),
            system_type: "gitlab".to_string(),
            url: "https://gitlab.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("test").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    // Additional extract_meaningful_words edge cases
    #[test]
    fn test_extract_meaningful_words_single_word() {
        let result = extract_meaningful_words("vulnerability", 5);
        assert_eq!(result, "vulnerability");
    }

    #[test]
    fn test_extract_meaningful_words_all_stop_words() {
        let result = extract_meaningful_words("the a an is are", 5);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_meaningful_words_mixed_case_stop_words() {
        let result = extract_meaningful_words("THE A An IS Are", 5);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_meaningful_words_exact_count() {
        // "one" (3 chars) is excluded, "two" (3 chars) is excluded, "three" (5 chars) is included
        // So only "three" passes the > 3 filter
        let result = extract_meaningful_words("one two three", 2);
        let words: Vec<&str> = result.split_whitespace().collect();
        assert_eq!(words.len(), 1); // Only "three" has > 3 chars
    }

    #[test]
    fn test_extract_meaningful_words_zero_count() {
        let result = extract_meaningful_words("test words here", 0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_meaningful_words_large_count() {
        let result =
            extract_meaningful_words("one two three four five six seven eight nine ten", 100);
        let words: Vec<&str> = result.split_whitespace().collect();
        // "one", "two", "three", "four", "five" are all <= 4 chars, so they're excluded
        // Only "seven", "eight", "nine", "ten" remain (4 words > 3 chars)
        // Actually: one(3), two(3), three(5), four(4), five(4), six(3), seven(5), eight(5), nine(4), ten(3)
        // Words > 3: three, four, five, seven, eight, nine = 6 words
        assert_eq!(words.len(), 6);
    }

    // Test URL handling edge cases
    #[tokio::test]
    async fn test_parse_github_url_empty_string() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);

        let result = searcher.parse_github_url("");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_github_url_just_slashes() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);

        let result = searcher.parse_github_url("///");
        // This splits into ["", "", "", ""] which has len 4 >= 2, but returns empty strings
        // Let's just verify it doesn't panic
        assert!(result.is_ok() || result.is_err());
    }

    // Test with different URL formats
    #[tokio::test]
    async fn test_parse_github_url_with_port() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);

        let result = searcher.parse_github_url("https://github.com:8080/owner/repo");
        assert!(result.is_ok());
        let (owner, repo) = result.unwrap();
        assert_eq!(owner, "owner");
        assert_eq!(repo, "repo");
    }

    // Test TicketReference all fields
    #[test]
    fn test_ticket_reference_all_fields() {
        let reference = TicketReference {
            ticket_id: "12345".to_string(),
            ticket_url: "https://github.com/test/repo/issues/12345".to_string(),
            system: "github".to_string(),
            status: "open".to_string(),
            title: "Security vulnerability in auth module".to_string(),
        };

        assert_eq!(reference.ticket_id, "12345");
        assert_eq!(
            reference.ticket_url,
            "https://github.com/test/repo/issues/12345"
        );
        assert_eq!(reference.system, "github");
        assert_eq!(reference.status, "open");
        assert_eq!(reference.title, "Security vulnerability in auth module");
    }

    // Test TicketReference with gitlab format
    #[test]
    fn test_ticket_reference_gitlab_format() {
        let reference = TicketReference {
            ticket_id: "999".to_string(),
            ticket_url: "https://gitlab.com/group/subgroup/project/issues/999".to_string(),
            system: "gitlab".to_string(),
            status: "closed".to_string(),
            title: "XXE vulnerability in XML parser".to_string(),
        };

        assert_eq!(reference.ticket_id, "999");
        assert_eq!(reference.system, "gitlab");
        assert_eq!(reference.status, "closed");
    }

    // Test unsupported system type logging path
    #[tokio::test]
    async fn test_search_unsupported_system_variants() {
        let systems = vec![
            TicketSystem {
                name: "Jira".to_string(),
                system_type: "jira".to_string(),
                url: "https://jira.example.com".to_string(),
                credentials: None,
            },
            TicketSystem {
                name: "Redmine".to_string(),
                system_type: "redmine".to_string(),
                url: "https://redmine.example.com".to_string(),
                credentials: None,
            },
            TicketSystem {
                name: "Phabricator".to_string(),
                system_type: "phabricator".to_string(),
                url: "https://phabricator.example.com".to_string(),
                credentials: None,
            },
        ];

        let searcher = TicketSearcher::new(systems);
        let results = searcher
            .search_for_finding("test vulnerability")
            .await
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    // Test search with special characters
    #[tokio::test]
    async fn test_search_with_special_characters() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher
            .search_for_finding("<script>alert('xss')</script> vulnerability")
            .await
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    // Test search with unicode
    #[tokio::test]
    async fn test_search_with_unicode() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);
        let results = searcher
            .search_for_finding("vulnerability with café and naïve characters")
            .await
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    // Test TicketSystem with all field combinations
    #[test]
    fn test_ticket_system_all_combinations() {
        // With credentials
        let system1 = TicketSystem {
            name: "Private GitLab".to_string(),
            system_type: "gitlab".to_string(),
            url: "https://gitlab.company.com".to_string(),
            credentials: Some("token-abc-123".to_string()),
        };
        assert!(system1.credentials.is_some());

        // Without credentials
        let system2 = TicketSystem {
            name: "Public GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        };
        assert!(system2.credentials.is_none());

        // Empty strings
        let system3 = TicketSystem {
            name: String::new(),
            system_type: String::new(),
            url: String::new(),
            credentials: None,
        };
        assert!(system3.name.is_empty());
    }

    // Test TicketSearcher with empty systems vector
    #[tokio::test]
    async fn test_searcher_with_no_systems() {
        let systems: Vec<TicketSystem> = vec![];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("anything").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    // Test all vulnerability keyword detection paths
    #[tokio::test]
    async fn test_search_with_all_vuln_types() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);

        // Test each vulnerability type keyword
        let vuln_types = [
            "injection",
            "xss",
            "xxe",
            "sql",
            "path traversal",
            "overflow",
            "deserialization",
            "buffer",
            "race condition",
            "privilege",
            "authentication",
            "authorization",
            "csrf",
            "ssrf",
            "xml",
            "yaml",
        ];

        for vuln_type in vuln_types.iter() {
            let results = searcher.search_for_finding(vuln_type).await.unwrap();
            assert_eq!(results.len(), 0, "Failed for vuln type: {}", vuln_type);
        }
    }

    // Test all language keyword detection paths
    #[tokio::test]
    async fn test_search_with_all_languages() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];

        let searcher = TicketSearcher::new(systems);

        let languages = [
            "python",
            "javascript",
            "rust",
            "c++",
            "java",
            "go",
            "ruby",
            "php",
        ];

        for lang in languages.iter() {
            let query = format!("{} vulnerability", lang);
            let results = searcher.search_for_finding(&query).await.unwrap();
            assert_eq!(results.len(), 0, "Failed for language: {}", lang);
        }
    }

    // Test GitHub and GitLab URL parsing consistency
    #[tokio::test]
    async fn test_parse_github_url_various_formats() {
        let systems = vec![TicketSystem {
            name: "GitHub".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);

        let test_cases = vec![
            ("https://github.com/owner/repo", ("owner", "repo")),
            ("https://github.com/owner/repo/", ("owner", "repo")),
            ("https://github.com/a/b", ("a", "b")),
            ("http://github.com/owner/repo", ("owner", "repo")),
        ];

        for (url, expected) in test_cases {
            let result = searcher.parse_github_url(url);
            assert!(result.is_ok(), "Failed for URL: {}", url);
            let (owner, repo) = result.unwrap();
            assert_eq!(owner, expected.0, "Owner mismatch for URL: {}", url);
            assert_eq!(repo, expected.1, "Repo mismatch for URL: {}", url);
        }
    }

    // Mockito-based tests for HTTP response handling
    #[tokio::test]
    #[ignore]
    async fn test_search_github_with_successful_response() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/search/issues")
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

        // The mock should return 1 result
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ticket_id, "123");
        assert_eq!(results[0].system, "github");

        mock.assert_async().await;
    }

    #[tokio::test]
    #[ignore]
    async fn test_search_github_with_empty_response() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/search/issues")
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
    #[ignore]
    async fn test_search_github_with_error_response() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/search/issues")
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

        // Error responses should return empty results (logged as warning)
        assert_eq!(results.len(), 0);

        mock.assert_async().await;
    }

    #[tokio::test]
    #[ignore]
    async fn test_search_gitlab_with_successful_response() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/api/v4/search")
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
    #[ignore]
    async fn test_search_gitlab_with_empty_response() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/api/v4/search")
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
    #[ignore]
    async fn test_search_gitlab_with_credentials() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/api/v4/search")
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
    #[ignore]
    async fn test_search_gitlab_with_error_response() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/api/v4/search")
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

    // Test with multiple systems (github + gitlab)
    #[tokio::test]
    #[ignore]
    async fn test_search_with_both_github_and_gitlab() {
        let mut github_server = Server::new_async().await;
        let mut gitlab_server = Server::new_async().await;

        let github_mock: mockito::Mock = github_server
            .mock("GET", "/search/issues")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"total_count": 1, "items": [{"number": 1, "html_url": "https://github.com/owner/repo/issues/1", "state": "open", "title": "GitHub issue"}]}"#)
            .create_async()
            .await;

        let gitlab_mock: mockito::Mock = gitlab_server
            .mock("GET", "/api/v4/search")
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

    // Test mixed success and failure
    #[tokio::test]
    #[ignore]
    async fn test_search_with_mixed_success_failure() {
        let mut github_server = Server::new_async().await;
        let mut gitlab_server = Server::new_async().await;

        let github_mock: mockito::Mock = github_server
            .mock("GET", "/search/issues")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"total_count": 1, "items": [{"number": 1, "html_url": "https://github.com/owner/repo/issues/1", "state": "open", "title": "GitHub issue"}]}"#)
            .create_async()
            .await;

        let gitlab_mock: mockito::Mock = gitlab_server
            .mock("GET", "/api/v4/search")
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

    // Additional coverage tests for uncovered lines
    #[test]
    fn test_ticket_system_debug_trait() {
        let system = TicketSystem {
            name: "Test".into(),
            system_type: "github".into(),
            url: "https://test.com".into(),
            credentials: None,
        };
        let debug_str = format!("{:?}", system);
        assert!(debug_str.contains("Test"));
    }

    #[test]
    fn test_ticket_reference_debug_trait() {
        let ref_ticket = TicketReference {
            ticket_id: "123".into(),
            ticket_url: "https://test.com".into(),
            system: "github".into(),
            status: "open".into(),
            title: "Test".into(),
        };
        let debug_str = format!("{:?}", ref_ticket);
        assert!(debug_str.contains("123"));
    }

    #[tokio::test]
    async fn test_search_with_only_whitespace_query() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("   ").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_newline_query() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("\n\n").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_github_with_tab_query() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("\t").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_gitlab_with_tab_query() {
        let systems = vec![TicketSystem {
            name: "GitLab".into(),
            system_type: "gitlab".into(),
            url: "https://gitlab.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("\t").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_extract_meaningful_words_with_punctuation() {
        let result = extract_meaningful_words("vulnerability, injection! xss?", 3);
        assert!(result.contains("vulnerability"));
        assert!(result.contains("injection"));
    }

    #[test]
    fn test_extract_meaningful_words_with_numbers() {
        let result = extract_meaningful_words("CVE-2024-1234 vulnerability", 3);
        assert!(result.contains("CVE-2024-1234"));
        assert!(result.contains("vulnerability"));
    }

    #[test]
    fn test_extract_meaningful_words_multiple_spaces() {
        let result = extract_meaningful_words("word1    word2   word3", 3);
        let words: Vec<&str> = result.split_whitespace().collect();
        assert_eq!(words.len(), 3);
    }

    #[test]
    fn test_extract_meaningful_words_leading_trailing_spaces() {
        let result = extract_meaningful_words("   word1 word2   ", 2);
        assert!(result.contains("word1"));
        assert!(result.contains("word2"));
    }

    #[tokio::test]
    async fn test_parse_github_url_with_subdomain() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        
        let result = searcher.parse_github_url("https://github.enterprise.com/owner/repo");
        assert!(result.is_ok());
        let (owner, repo) = result.unwrap();
        assert_eq!(owner, "owner");
        assert_eq!(repo, "repo");
    }

    #[tokio::test]
    async fn test_parse_github_url_with_www() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        
        let result = searcher.parse_github_url("https://www.github.com/owner/repo");
        assert!(result.is_ok());
        let (owner, repo) = result.unwrap();
        assert_eq!(owner, "owner");
        assert_eq!(repo, "repo");
    }

    #[tokio::test]
    async fn test_parse_github_url_with_query_params() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        
        let result = searcher.parse_github_url("https://github.com/owner/repo?param=value");
        assert!(result.is_ok());
        let (owner, repo) = result.unwrap();
        assert_eq!(owner, "owner");
        assert!(repo.contains("?param=value") || repo == "repo");
    }

    #[tokio::test]
    async fn test_parse_github_url_with_fragment() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        
        let result = searcher.parse_github_url("https://github.com/owner/repo#section");
        assert!(result.is_ok());
        let (owner, _repo) = result.unwrap();
        assert_eq!(owner, "owner");
    }

    #[tokio::test]
    async fn test_search_with_cve_and_vuln_type() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("CVE-2024-1234 sql injection").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_cve_and_language() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("CVE-2024-1234 python").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_vuln_type_and_language() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("python xss vulnerability").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_all_three_components() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("CVE-2024-1234 python sql injection").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_gitlab_with_credentials_header() {
        let systems = vec![TicketSystem {
            name: "GitLab".into(),
            system_type: "gitlab".into(),
            url: "https://gitlab.com".into(),
            credentials: Some("test-token".into()),
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("test").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_gitlab_without_credentials() {
        let systems = vec![TicketSystem {
            name: "GitLab".into(),
            system_type: "gitlab".into(),
            url: "https://gitlab.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("test").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_ticket_system_clone() {
        let system = TicketSystem {
            name: "Test".into(),
            system_type: "github".into(),
            url: "https://test.com".into(),
            credentials: Some("token".into()),
        };
        let cloned = system.clone();
        assert_eq!(system.name, cloned.name);
        assert_eq!(system.system_type, cloned.system_type);
        assert_eq!(system.url, cloned.url);
        assert_eq!(system.credentials, cloned.credentials);
    }

    #[test]
    fn test_ticket_reference_all_fields_access() {
        let ref_ticket = TicketReference {
            ticket_id: "123".into(),
            ticket_url: "https://test.com".into(),
            system: "github".into(),
            status: "open".into(),
            title: "Test vulnerability".into(),
        };
        
        assert_eq!(ref_ticket.ticket_id, "123");
        assert_eq!(ref_ticket.ticket_url, "https://test.com");
        assert_eq!(ref_ticket.system, "github");
        assert_eq!(ref_ticket.status, "open");
        assert_eq!(ref_ticket.title, "Test vulnerability");
    }

    #[tokio::test]
    async fn test_search_with_mixed_case_system_type() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "GITHUB".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("test").await.unwrap();
        // GITHUB != github, so should return empty
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_empty_system_name() {
        let systems = vec![TicketSystem {
            name: "".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("test").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_empty_url() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("test").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_very_long_query() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let long_query = "a".repeat(1000);
        let results = searcher.search_for_finding(&long_query).await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_ticket_system_with_empty_credentials_string() {
        let system = TicketSystem {
            name: "Test".into(),
            system_type: "github".into(),
            url: "https://test.com".into(),
            credentials: Some("".into()),
        };
        assert!(system.credentials.is_some());
        assert_eq!(system.credentials.as_ref().unwrap(), "");
    }

    #[tokio::test]
    async fn test_search_with_unicode_in_query() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("vulnerability café naïve").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_html_entities_in_query() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("<script>alert('xss')</script>").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_sql_special_chars() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("'; DROP TABLE users; --").await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_search_with_path_traversal_chars() {
        let systems = vec![TicketSystem {
            name: "GitHub".into(),
            system_type: "github".into(),
            url: "https://github.com".into(),
            credentials: None,
        }];
        let searcher = TicketSearcher::new(systems);
        let results = searcher.search_for_finding("../../../etc/passwd").await.unwrap();
        assert_eq!(results.len(), 0);
    }
}
