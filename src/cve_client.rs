//! CVE Bootstrap HTTP Client
//!
//! Async client for fetching CVE data from:
//! - CISA Known Exploited Vulnerabilities (KEV) catalog
//! - NVD (National Vulnerability Database) API

use crate::scanner_types::{CveEntry, CveSource, V3Severity};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::warn;

/// CVE bootstrap HTTP client
pub struct CveClient {
    http: Client,
}

impl Default for CveClient {
    fn default() -> Self {
        Self::new()
    }
}

impl CveClient {
    /// Create a new CVE client with default settings
    pub fn new() -> Self {
        Self {
            http: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Fetch CISA KEV catalog
    ///
    /// Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    pub async fn fetch_kev_catalog(&self) -> Result<Vec<CveEntry>, Box<dyn std::error::Error>> {
        let url =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

        let response = self.http.get(url).send().await?;

        if !response.status().is_success() {
            warn!(
                "KEV catalog returned status: {}, returning empty list",
                response.status()
            );
            return Ok(Vec::new());
        }

        // Try to get raw text first for better error debugging
        let text = response.text().await?;

        // Try to parse as JSON
        match serde_json::from_str::<KeVResponse>(&text) {
            Ok(kev_response) => {
                let entries: Vec<CveEntry> = kev_response
                    .vulnerabilities
                    .into_iter()
                    .map(|vuln| CveEntry {
                        cve_id: vuln.cve_id,
                        description: vuln.short_description,
                        severity: map_cve_severity(map_kev_severity(&vuln.severity)),
                        source: CveSource::KEV,
                        affected_products: vec![],
                        published_date: Some(vuln.date_added),
                    })
                    .collect();

                Ok(entries)
            }
            Err(e) => {
                // Log a debug level for JSON parse errors - API format might have changed
                tracing::debug!(
                    "KEV catalog JSON parse error (API format may have changed): {}",
                    e
                );
                tracing::debug!(
                    "Response preview: {}",
                    text.chars().take(200).collect::<String>()
                );
                Ok(Vec::new())
            }
        }
    }

    /// Fetch CVEs from NVD API
    ///
    /// Source: https://services.nvd.nist.gov/rest/json/cves/2.0
    pub async fn fetch_nvd_cves(
        &self,
        vendor: &str,
        product: &str,
    ) -> Result<Vec<CveEntry>, Box<dyn std::error::Error>> {
        let query = format!("{}+{}", vendor, product);
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}",
            urlencoding::encode(&query)
        );

        let response = self.http.get(&url).send().await?;

        if response.status().as_u16() == 403 {
            warn!("NVD API rate limited (403), returning empty list");
            return Ok(Vec::new());
        }

        if !response.status().is_success() {
            warn!(
                "NVD API returned status: {}, returning empty list",
                response.status()
            );
            return Ok(Vec::new());
        }

        let nvd_response: NvdResponse = response.json().await?;

        let entries: Vec<CveEntry> = nvd_response
            .vulnerabilities
            .into_iter()
            .take(100) // Limit to first 100 results
            .map(|vuln| {
                let cve_id = vuln.id;
                let description = vuln
                    .descriptions
                    .first()
                    .map(|d| d.value.clone())
                    .unwrap_or_default();

                let severity = vuln
                    .metrics
                    .as_ref()
                    .and_then(|m| m.cvss_metric_v31.first())
                    .map(|m| map_nvd_severity(&m.severity))
                    .unwrap_or(CveSeverity::Medium);

                CveEntry {
                    cve_id,
                    description,
                    severity: map_cve_severity(severity),
                    source: CveSource::NVD,
                    affected_products: vec![],
                    published_date: vuln.published,
                }
            })
            .collect();

        Ok(entries)
    }

    /// Deduplicate CVE entries, KEV takes priority over NVD
    pub fn dedup_cve_entries(kev: Vec<CveEntry>, nvd: Vec<CveEntry>) -> Vec<CveEntry> {
        let mut result: std::collections::HashMap<String, CveEntry> =
            std::collections::HashMap::new();

        // KEV entries take priority
        for entry in kev {
            let cve_id = entry.cve_id.clone();
            result.insert(cve_id, entry);
        }

        // NVD entries only if not already in KEV
        for entry in nvd {
            let cve_id = entry.cve_id.clone();
            result.entry(cve_id).or_insert(entry);
        }

        result.into_values().collect()
    }
}

/// KEV catalog response structure
#[derive(Debug, Serialize, Deserialize)]
struct KeVResponse {
    vulnerabilities: Vec<KeVVulnerability>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeVVulnerability {
    cve_id: String,
    short_description: String,
    severity: String,
    date_added: String,
}

/// NVD API response structure
#[derive(Debug, Serialize, Deserialize)]
struct NvdResponse {
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NvdVulnerability {
    id: String,
    descriptions: Vec<NvdDescription>,
    metrics: Option<NvdMetrics>,
    published: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NvdDescription {
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NvdMetrics {
    cvss_metric_v31: Vec<NvdCvssV31>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NvdCvssV31 {
    severity: String,
}

/// Severity from NVD API
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CveSeverity {
    Low,
    Medium,
    High,
    Critical,
}

fn map_kev_severity(severity: &str) -> CveSeverity {
    match severity.to_lowercase().as_str() {
        "critical" => CveSeverity::Critical,
        "high" => CveSeverity::High,
        "medium" => CveSeverity::Medium,
        "low" => CveSeverity::Low,
        _ => CveSeverity::Medium,
    }
}

fn map_nvd_severity(severity: &str) -> CveSeverity {
    match severity.to_lowercase().as_str() {
        "critical" => CveSeverity::Critical,
        "high" => CveSeverity::High,
        "medium" => CveSeverity::Medium,
        "low" => CveSeverity::Low,
        _ => CveSeverity::Medium,
    }
}

fn map_cve_severity(severity: CveSeverity) -> V3Severity {
    match severity {
        CveSeverity::Critical => V3Severity::Critical,
        CveSeverity::High => V3Severity::High,
        CveSeverity::Medium => V3Severity::Medium,
        CveSeverity::Low => V3Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner_types::V3Severity;
    use serde_json::json;

    #[tokio::test]
    async fn test_parse_kev_response() {
        let mock_json = json!({
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-1234",
                    "short_description": "Test vulnerability in product X",
                    "severity": "high",
                    "date_added": "2024-01-15"
                },
                {
                    "cve_id": "CVE-2024-5678",
                    "short_description": "Another vulnerability",
                    "severity": "critical",
                    "date_added": "2024-02-20"
                }
            ]
        });

        let response: KeVResponse = serde_json::from_value(mock_json).unwrap();

        assert_eq!(response.vulnerabilities.len(), 2);
        assert_eq!(response.vulnerabilities[0].cve_id, "CVE-2024-1234");
        assert_eq!(response.vulnerabilities[0].severity, "high");
    }

    #[tokio::test]
    async fn test_dedup_kev_priority() {
        let kev = vec![CveEntry {
            cve_id: "CVE-2024-1234".to_string(),
            description: "KEV description".to_string(),
            severity: V3Severity::High,
            source: CveSource::KEV,
            affected_products: vec![],
            published_date: None,
        }];

        let nvd = vec![
            CveEntry {
                cve_id: "CVE-2024-1234".to_string(),
                description: "NVD description".to_string(),
                severity: V3Severity::Medium,
                source: CveSource::NVD,
                affected_products: vec![],
                published_date: None,
            },
            CveEntry {
                cve_id: "CVE-2024-9999".to_string(),
                description: "NVD only CVE".to_string(),
                severity: V3Severity::Low,
                source: CveSource::NVD,
                affected_products: vec![],
                published_date: None,
            },
        ];

        let result = CveClient::dedup_cve_entries(kev, nvd);

        assert_eq!(result.len(), 2);

        let cve_1234 = result.iter().find(|e| e.cve_id == "CVE-2024-1234").unwrap();
        assert_eq!(cve_1234.source, CveSource::KEV);
        assert_eq!(cve_1234.description, "KEV description");

        let cve_9999 = result.iter().find(|e| e.cve_id == "CVE-2024-9999").unwrap();
        assert_eq!(cve_9999.source, CveSource::NVD);
    }

    #[tokio::test]
    async fn test_dedup_empty_inputs() {
        let result = CveClient::dedup_cve_entries(vec![], vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_map_kev_severity() {
        assert_eq!(map_kev_severity("critical"), CveSeverity::Critical);
        assert_eq!(map_kev_severity("HIGH"), CveSeverity::High);
        assert_eq!(map_kev_severity("medium"), CveSeverity::Medium);
        assert_eq!(map_kev_severity("low"), CveSeverity::Low);
        assert_eq!(map_kev_severity("unknown"), CveSeverity::Medium);
    }

    #[test]
    fn test_map_nvd_severity() {
        assert_eq!(map_nvd_severity("critical"), CveSeverity::Critical);
        assert_eq!(map_nvd_severity("high"), CveSeverity::High);
        assert_eq!(map_nvd_severity("MEDIUM"), CveSeverity::Medium);
        assert_eq!(map_nvd_severity("low"), CveSeverity::Low);
    }

    #[test]
    fn test_map_cve_severity() {
        assert_eq!(
            map_cve_severity(CveSeverity::Critical),
            V3Severity::Critical
        );
        assert_eq!(map_cve_severity(CveSeverity::High), V3Severity::High);
        assert_eq!(map_cve_severity(CveSeverity::Medium), V3Severity::Medium);
        assert_eq!(map_cve_severity(CveSeverity::Low), V3Severity::Low);
    }

    #[tokio::test]
    async fn test_parse_kev_empty_vulnerabilities() {
        let mock_json = json!({
            "vulnerabilities": []
        });

        let response: KeVResponse = serde_json::from_value(mock_json).unwrap();
        assert_eq!(response.vulnerabilities.len(), 0);
    }

    #[tokio::test]
    async fn test_parse_kev_invalid_json() {
        let invalid_json = r#"{"invalid": json}"#;
        let result: Result<KeVResponse, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_map_kev_severity_case_insensitive() {
        // Test all case variations
        assert_eq!(map_kev_severity("CRITICAL"), CveSeverity::Critical);
        assert_eq!(map_kev_severity("Critical"), CveSeverity::Critical);
        assert_eq!(map_kev_severity("critical"), CveSeverity::Critical);
        assert_eq!(map_kev_severity("HIGH"), CveSeverity::High);
        assert_eq!(map_kev_severity("High"), CveSeverity::High);
        assert_eq!(map_kev_severity("high"), CveSeverity::High);
    }

    #[test]
    fn test_map_kev_severity_unknown_defaults_to_medium() {
        assert_eq!(map_kev_severity("unknown"), CveSeverity::Medium);
        assert_eq!(map_kev_severity(""), CveSeverity::Medium);
        assert_eq!(map_kev_severity("invalid"), CveSeverity::Medium);
        assert_eq!(map_kev_severity("info"), CveSeverity::Medium);
    }

    #[test]
    fn test_map_nvd_severity_unknown_defaults_to_medium() {
        assert_eq!(map_nvd_severity("unknown"), CveSeverity::Medium);
        assert_eq!(map_nvd_severity(""), CveSeverity::Medium);
        assert_eq!(map_nvd_severity("invalid"), CveSeverity::Medium);
    }

    #[tokio::test]
    async fn test_dedup_multiple_kev_entries() {
        let kev = vec![
            CveEntry {
                cve_id: "CVE-2024-1111".to_string(),
                description: "KEV 1".to_string(),
                severity: V3Severity::High,
                source: CveSource::KEV,
                affected_products: vec!["product1".to_string()],
                published_date: Some("2024-01-01".to_string()),
            },
            CveEntry {
                cve_id: "CVE-2024-2222".to_string(),
                description: "KEV 2".to_string(),
                severity: V3Severity::Critical,
                source: CveSource::KEV,
                affected_products: vec![],
                published_date: None,
            },
        ];

        let nvd = vec![
            CveEntry {
                cve_id: "CVE-2024-1111".to_string(),
                description: "NVD duplicate".to_string(),
                severity: V3Severity::Medium,
                source: CveSource::NVD,
                affected_products: vec![],
                published_date: None,
            },
            CveEntry {
                cve_id: "CVE-2024-3333".to_string(),
                description: "NVD only".to_string(),
                severity: V3Severity::Low,
                source: CveSource::NVD,
                affected_products: vec![],
                published_date: None,
            },
        ];

        let result = CveClient::dedup_cve_entries(kev, nvd);

        assert_eq!(result.len(), 3);

        // CVE-2024-1111 should have KEV source
        let entry = result.iter().find(|e| e.cve_id == "CVE-2024-1111").unwrap();
        assert_eq!(entry.source, CveSource::KEV);
        assert_eq!(entry.description, "KEV 1");

        // CVE-2024-2222 should only exist once
        let entry = result.iter().find(|e| e.cve_id == "CVE-2024-2222").unwrap();
        assert_eq!(entry.source, CveSource::KEV);

        // CVE-2024-3333 should have NVD source
        let entry = result.iter().find(|e| e.cve_id == "CVE-2024-3333").unwrap();
        assert_eq!(entry.source, CveSource::NVD);
    }

    #[tokio::test]
    async fn test_dedup_only_nvd() {
        let kev = vec![];
        let nvd = vec![CveEntry {
            cve_id: "CVE-2024-1111".to_string(),
            description: "NVD only".to_string(),
            severity: V3Severity::Medium,
            source: CveSource::NVD,
            affected_products: vec![],
            published_date: None,
        }];

        let result = CveClient::dedup_cve_entries(kev, nvd);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].source, CveSource::NVD);
    }

    #[tokio::test]
    async fn test_dedup_only_kev() {
        let kev = vec![CveEntry {
            cve_id: "CVE-2024-1111".to_string(),
            description: "KEV only".to_string(),
            severity: V3Severity::High,
            source: CveSource::KEV,
            affected_products: vec![],
            published_date: None,
        }];
        let nvd = vec![];

        let result = CveClient::dedup_cve_entries(kev, nvd);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].source, CveSource::KEV);
    }

    #[test]
    fn test_new_client() {
        let _client = CveClient::new();
        // Just verify it creates successfully
    }
}
