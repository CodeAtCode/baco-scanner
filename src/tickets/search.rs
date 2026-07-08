use std::time::Duration;

use serde::Deserialize;

use super::config::{TicketReference, TicketSystem};

/// Helper to extract meaningful words from a string, excluding common stop words
pub(super) fn extract_meaningful_words(s: &str, count: usize) -> String {
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

/// Searches for tickets (issues) in configured ticket systems
pub struct TicketSearcher {
    pub(crate) systems: Vec<TicketSystem>,
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
                    Err(e) => tracing::debug!("GitHub search failed (expected in some cases): {}", e),
                },
                "gitlab" => match self.search_gitlab(system, finding).await {
                    Ok(Some(ticket)) => matches.push(ticket),
                    Ok(None) => {}
                    Err(e) => tracing::debug!("GitLab search failed (expected in some cases): {}", e),
                },
                _ => {
                    tracing::debug!("Unsupported ticket system: {}", system.system_type);
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
                    // 404 is expected when no results match the query
                    if response.status().as_u16() == 404 {
                        tracing::debug!(
                            "GitHub search returned 404 for query: {}",
                            query
                        );
                    } else {
                        tracing::warn!(
                            "GitHub search returned status {} for query: {}",
                            response.status(),
                            query
                        );
                    }
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
    pub(crate) fn parse_github_url(&self, url: &str) -> Result<(String, String), String> {
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
