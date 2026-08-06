//! CVE client network tests using mockito
//!
//! Tests cover:
//! - fetch_kev_catalog happy path: valid JSON returns entries with correct fields
//! - fetch_kev_catalog HTTP error: 500 returns empty Vec
//! - fetch_kev_catalog malformed JSON: invalid JSON returns empty Vec
//! - fetch_nvd_cves happy path: valid JSON returns entries limited to 100
//! - fetch_nvd_cves 403 rate-limit: returns empty Vec
//! - fetch_nvd_cves HTTP error: 500 returns empty Vec

use baco::cve_client::CveClient;
use baco::scanner_types::cve::CveSource;
use baco::scanner_types::severity::V3Severity;
use reqwest::Client;

// ============================================================================
// KEV Catalog Tests
// ============================================================================

#[tokio::test]
async fn test_fetch_kev_catalog_happy_path() {
    let mut server = mockito::Server::new_async().await;

    let mock_json = r#"{
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
    }"#;

    let _mock = server
        .mock("GET", "/known_exploited_vulnerabilities.json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_json)
        .create();

    let http_client = Client::new();
    let mut client = CveClient::with_http_client(http_client);
    client.set_base_url(server.url());

    let result = client.fetch_kev_catalog().await;
    assert!(result.is_ok());
    let entries = result.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].cve_id, "CVE-2024-1234");
    assert_eq!(entries[0].description, "Test vulnerability in product X");
    assert_eq!(entries[0].severity, V3Severity::High);
    assert_eq!(entries[0].source, CveSource::KEV);
    assert_eq!(entries[0].published_date, Some("2024-01-15".to_string()));
}

#[tokio::test]
async fn test_fetch_kev_catalog_http_error() {
    let mut server = mockito::Server::new_async().await;

    let _mock = server
        .mock("GET", "/known_exploited_vulnerabilities.json")
        .with_status(500)
        .create();

    let http_client = Client::new();
    let mut client = CveClient::with_http_client(http_client);
    client.set_base_url(server.url());

    let result = client.fetch_kev_catalog().await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_fetch_kev_catalog_malformed_json() {
    let mut server = mockito::Server::new_async().await;

    let _mock = server
        .mock("GET", "/known_exploited_vulnerabilities.json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("invalid json {")
        .create();

    let http_client = Client::new();
    let mut client = CveClient::with_http_client(http_client);
    client.set_base_url(server.url());

    let result = client.fetch_kev_catalog().await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

// ============================================================================
// NVD CVEs Tests
// ============================================================================

#[tokio::test]
async fn test_fetch_nvd_cves_happy_path() {
    let mut server = mockito::Server::new_async().await;

    let mock_json = r#"{
        "vulnerabilities": [
            {
                "id": "CVE-2024-1111",
                "descriptions": [{"value": "NVD vulnerability description"}],
                "metrics": {
                    "cvssMetricV31": [{"severity": "high"}]
                },
                "published": "2024-01-10"
            },
            {
                "id": "CVE-2024-2222",
                "descriptions": [{"value": "Another NVD vulnerability"}],
                "metrics": {
                    "cvssMetricV31": [{"severity": "critical"}]
                },
                "published": "2024-02-15"
            }
        ]
    }"#;

    let _mock = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_json)
        .create();

    let http_client = Client::new();
    let mut client = CveClient::with_http_client(http_client);
    client.set_base_url(server.url());

    let result = client.fetch_nvd_cves("vendor", "product").await;
    assert!(result.is_ok());
    let entries = result.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].cve_id, "CVE-2024-1111");
    assert_eq!(entries[0].source, CveSource::NVD);
}

#[tokio::test]
async fn test_fetch_nvd_cves_rate_limit_403() {
    let mut server = mockito::Server::new_async().await;

    let _mock = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(403)
        .create();

    let http_client = Client::new();
    let mut client = CveClient::with_http_client(http_client);
    client.set_base_url(server.url());

    let result = client.fetch_nvd_cves("vendor", "product").await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_fetch_nvd_cves_http_error() {
    let mut server = mockito::Server::new_async().await;

    let _mock = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .create();

    let http_client = Client::new();
    let mut client = CveClient::with_http_client(http_client);
    client.set_base_url(server.url());

    let result = client.fetch_nvd_cves("vendor", "product").await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}
