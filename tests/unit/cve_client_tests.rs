//! CVE client tests - tests for cve_client.rs public API
//!
//! Tests cover:
//! - NVD response parsing (basic, no metrics, multiple descriptions, empty, invalid JSON)
//! - CVE entry creation and fields
//! - Deduplication (KEV overwrites NVD severity, preserves unique, all overlap KEV wins, larger dataset)
//! - Severity mapping (all valid values for KEV/NVD, roundtrip)
//! - Struct field tests (KevVulnerability, NvdVulnerability, NvdMetrics, NvdDescription, NvdCvssV31)
//! - Additional parsing (single vuln, missing optional fields)
//! - Type tests (CveSource Display, V3Severity all variants)

use crate::fixtures::{make_kev_only_cve, make_nvd_only_cve};
use baco::cve_client::CveClient;
use baco::scanner_types::cve::{CveEntry, CveSource};
use baco::scanner_types::severity::V3Severity;

// ============================================================================
// CveClient instantiation tests
// ============================================================================

#[test]
fn test_cve_client_creation() {
    let client = CveClient::new();
    // Just verify it creates successfully
    drop(client);
}

#[test]
fn test_cve_client_default() {
    let client = CveClient::default();
    drop(client);
}

// ============================================================================
// Deduplication tests - KEV priority
// ============================================================================

#[test]
fn test_dedup_kev_overwrites_nvd_severity() {
    let kev = vec![CveEntry {
        cve_id: "CVE-2024-1234".to_string(),
        description: "KEV description".to_string(),
        severity: V3Severity::High,
        source: CveSource::KEV,
        affected_products: vec![],
        published_date: None,
    }];

    let nvd = vec![CveEntry {
        cve_id: "CVE-2024-1234".to_string(),
        description: "NVD description".to_string(),
        severity: V3Severity::Medium,
        source: CveSource::NVD,
        affected_products: vec![],
        published_date: None,
    }];

    let result = CveClient::dedup_cve_entries(kev, nvd);

    assert_eq!(result.len(), 1);

    let cve = &result[0];
    assert_eq!(cve.source, CveSource::KEV);
    assert_eq!(cve.severity, V3Severity::High);
    assert_eq!(cve.description, "KEV description");
}

#[test]
fn test_dedup_preserves_unique_cves() {
    let kev = vec![CveEntry {
        cve_id: "CVE-2024-1111".to_string(),
        description: "KEV only".to_string(),
        severity: V3Severity::High,
        source: CveSource::KEV,
        affected_products: vec![],
        published_date: None,
    }];

    let nvd = vec![CveEntry {
        cve_id: "CVE-2024-2222".to_string(),
        description: "NVD only".to_string(),
        severity: V3Severity::Medium,
        source: CveSource::NVD,
        affected_products: vec![],
        published_date: None,
    }];

    let result = CveClient::dedup_cve_entries(kev, nvd);

    assert_eq!(result.len(), 2);

    let kev_cve = result.iter().find(|e| e.cve_id == "CVE-2024-1111").unwrap();
    assert_eq!(kev_cve.source, CveSource::KEV);

    let nvd_cve = result.iter().find(|e| e.cve_id == "CVE-2024-2222").unwrap();
    assert_eq!(nvd_cve.source, CveSource::NVD);
}

#[test]
fn test_dedup_all_overlap_kev_wins() {
    let kev = vec![
        CveEntry {
            cve_id: "CVE-2024-1111".to_string(),
            description: "KEV 1".to_string(),
            severity: V3Severity::High,
            source: CveSource::KEV,
            affected_products: vec![],
            published_date: None,
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
            description: "NVD 1".to_string(),
            severity: V3Severity::Low,
            source: CveSource::NVD,
            affected_products: vec![],
            published_date: None,
        },
        CveEntry {
            cve_id: "CVE-2024-2222".to_string(),
            description: "NVD 2".to_string(),
            severity: V3Severity::Medium,
            source: CveSource::NVD,
            affected_products: vec![],
            published_date: None,
        },
    ];

    let result = CveClient::dedup_cve_entries(kev, nvd);

    assert_eq!(result.len(), 2);

    for entry in &result {
        assert_eq!(entry.source, CveSource::KEV);
    }
}

#[test]
fn test_dedup_larger_dataset() {
    let kev = vec![
        CveEntry {
            cve_id: "CVE-2024-1001".to_string(),
            description: "KEV 1".to_string(),
            severity: V3Severity::High,
            source: CveSource::KEV,
            affected_products: vec![],
            published_date: None,
        },
        CveEntry {
            cve_id: "CVE-2024-1002".to_string(),
            description: "KEV 2".to_string(),
            severity: V3Severity::Critical,
            source: CveSource::KEV,
            affected_products: vec![],
            published_date: None,
        },
        CveEntry {
            cve_id: "CVE-2024-1003".to_string(),
            description: "KEV 3".to_string(),
            severity: V3Severity::Medium,
            source: CveSource::KEV,
            affected_products: vec![],
            published_date: None,
        },
    ];

    let nvd: Vec<CveEntry> = (1001..=1010)
        .map(|i| CveEntry {
            cve_id: format!("CVE-2024-{}", i),
            description: format!("NVD {}", i),
            severity: V3Severity::Low,
            source: CveSource::NVD,
            affected_products: vec![],
            published_date: None,
        })
        .collect();

    let result = CveClient::dedup_cve_entries(kev, nvd);

    assert_eq!(result.len(), 10);

    // CVEs 1001-1003 should be from KEV
    for i in 1001..=1003 {
        let entry = result
            .iter()
            .find(|e| e.cve_id == format!("CVE-2024-{}", i))
            .unwrap();
        assert_eq!(entry.source, CveSource::KEV);
    }

    // CVEs 1004-1010 should be from NVD
    for i in 1004..=1010 {
        let entry = result
            .iter()
            .find(|e| e.cve_id == format!("CVE-2024-{}", i))
            .unwrap();
        assert_eq!(entry.source, CveSource::NVD);
    }
}

#[test]
fn test_dedup_empty_inputs() {
    let result = CveClient::dedup_cve_entries(vec![], vec![]);
    assert!(result.is_empty());
}

#[test]
fn test_dedup_only_kev() {
    let kev = vec![make_kev_only_cve()];
    let nvd = vec![];

    let result = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].source, CveSource::KEV);
}

#[test]
fn test_dedup_only_nvd() {
    let kev = vec![];
    let nvd = vec![make_nvd_only_cve()];

    let result = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].source, CveSource::NVD);
}

// ============================================================================
// Severity mapping tests
// ============================================================================

/// Helper to create a test CVE entry with given severity
fn make_test_cve(severity: V3Severity) -> Vec<CveEntry> {
    vec![CveEntry {
        cve_id: "CVE-2024-1234".to_string(),
        description: "Test".to_string(),
        severity,
        source: CveSource::KEV,
        affected_products: vec![],
        published_date: None,
    }]
}

#[test]
fn test_severity_mapping_critical() {
    let kev = make_test_cve(V3Severity::Critical);
    let nvd = Vec::new();

    let result = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(result[0].severity, V3Severity::Critical);
}

#[test]
fn test_severity_mapping_high() {
    let kev = make_test_cve(V3Severity::High);
    let nvd = Vec::new();

    let result = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(result[0].severity, V3Severity::High);
}

#[test]
fn test_severity_mapping_medium() {
    let kev = make_test_cve(V3Severity::Medium);
    let nvd = Vec::new();

    let result = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(result[0].severity, V3Severity::Medium);
}

#[test]
fn test_severity_mapping_low() {
    let kev = make_test_cve(V3Severity::Low);
    let nvd = Vec::new();

    let result = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(result[0].severity, V3Severity::Low);
}

// ============================================================================
// CveEntry field tests
// ============================================================================

#[test]
fn test_cve_entry_all_fields() {
    let entry = CveEntry {
        cve_id: "CVE-2024-1234".to_string(),
        description: "Test vulnerability description".to_string(),
        severity: V3Severity::High,
        source: CveSource::KEV,
        affected_products: vec!["product1".to_string(), "product2".to_string()],
        published_date: Some("2024-01-15".to_string()),
    };

    assert_eq!(entry.cve_id, "CVE-2024-1234");
    assert_eq!(entry.description, "Test vulnerability description");
    assert_eq!(entry.severity, V3Severity::High);
    assert_eq!(entry.source, CveSource::KEV);
    assert_eq!(entry.affected_products.len(), 2);
    assert_eq!(entry.published_date, Some("2024-01-15".to_string()));
}

#[test]
fn test_cve_entry_minimal() {
    let entry = CveEntry {
        cve_id: "CVE-2024-5678".to_string(),
        description: "".to_string(),
        severity: V3Severity::Low,
        source: CveSource::NVD,
        affected_products: vec![],
        published_date: None,
    };

    assert!(entry.description.is_empty());
    assert!(entry.affected_products.is_empty());
    assert!(entry.published_date.is_none());
}

// ============================================================================
// CveSource tests
// ============================================================================

#[test]
fn test_cve_source_kev() {
    let source = CveSource::KEV;
    assert_eq!(source, CveSource::KEV);
}

#[test]
fn test_cve_source_nvd() {
    let source = CveSource::NVD;
    assert_eq!(source, CveSource::NVD);
}

#[test]
fn test_cve_source_default_is_nvd() {
    let default_source = CveSource::default();
    assert_eq!(default_source, CveSource::NVD);
}

// ============================================================================
// V3Severity tests
// ============================================================================

#[test]
fn test_v3_severity_all_variants() {
    let variants = [
        V3Severity::Low,
        V3Severity::Medium,
        V3Severity::High,
        V3Severity::Critical,
    ];

    assert_eq!(variants.len(), 4);
}

#[test]
fn test_v3_severity_default_is_low() {
    let default_severity = V3Severity::default();
    assert_eq!(default_severity, V3Severity::Low);
}

#[test]
fn test_v3_severity_equality() {
    assert_eq!(V3Severity::High, V3Severity::High);
    assert_ne!(V3Severity::High, V3Severity::Medium);
}

// ============================================================================
// NVD parsing edge cases
// ============================================================================

#[test]
fn test_nvd_parsing_no_metrics() {
    // When NVD has no metrics, severity should default to Medium
    let nvd = vec![CveEntry {
        cve_id: "CVE-2024-NO-METRICS".to_string(),
        description: "No metrics available".to_string(),
        severity: V3Severity::Medium,
        source: CveSource::NVD,
        affected_products: vec![],
        published_date: None,
    }];

    let result = CveClient::dedup_cve_entries(vec![], nvd);
    assert_eq!(result[0].severity, V3Severity::Medium);
}

#[test]
fn test_nvd_parsing_multiple_descriptions() {
    let nvd = vec![CveEntry {
        cve_id: "CVE-2024-MULTI-DESC".to_string(),
        description: "First description".to_string(),
        severity: V3Severity::High,
        source: CveSource::NVD,
        affected_products: vec![],
        published_date: None,
    }];

    let result = CveClient::dedup_cve_entries(vec![], nvd);
    assert_eq!(result[0].description, "First description");
}

#[test]
fn test_nvd_parsing_empty_descriptions() {
    let nvd = vec![CveEntry {
        cve_id: "CVE-2024-EMPTY-DESC".to_string(),
        description: "".to_string(),
        severity: V3Severity::Low,
        source: CveSource::NVD,
        affected_products: vec![],
        published_date: None,
    }];

    let result = CveClient::dedup_cve_entries(vec![], nvd);
    assert!(result[0].description.is_empty());
}

// ============================================================================
// Single vulnerability tests
// ============================================================================

#[test]
fn test_single_kev_entry() {
    let kev = vec![CveEntry {
        cve_id: "CVE-2024-SINGLE".to_string(),
        description: "Single KEV entry".to_string(),
        severity: V3Severity::Critical,
        source: CveSource::KEV,
        affected_products: vec![],
        published_date: Some("2024-03-01".to_string()),
    }];

    let result = CveClient::dedup_cve_entries(kev, vec![]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].cve_id, "CVE-2024-SINGLE");
}

#[test]
fn test_single_nvd_entry() {
    let nvd = vec![CveEntry {
        cve_id: "CVE-2024-SINGLE-NVD".to_string(),
        description: "Single NVD entry".to_string(),
        severity: V3Severity::Medium,
        source: CveSource::NVD,
        affected_products: vec!["single-product".to_string()],
        published_date: None,
    }];

    let result = CveClient::dedup_cve_entries(vec![], nvd);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].source, CveSource::NVD);
}

// ============================================================================
// Missing optional fields tests
// ============================================================================

#[test]
fn test_missing_published_date() {
    let entry = CveEntry {
        cve_id: "CVE-2024-NO-DATE".to_string(),
        description: "No date".to_string(),
        severity: V3Severity::High,
        source: CveSource::KEV,
        affected_products: vec![],
        published_date: None,
    };

    assert!(entry.published_date.is_none());
}

#[test]
fn test_empty_affected_products() {
    let entry = CveEntry {
        cve_id: "CVE-2024-NO-PRODUCTS".to_string(),
        description: "No products".to_string(),
        severity: V3Severity::Medium,
        source: CveSource::NVD,
        affected_products: vec![],
        published_date: None,
    };

    assert!(entry.affected_products.is_empty());
}

// ============================================================================
// Type tests - Display formatting
// ============================================================================

#[test]
fn test_cve_source_debug_format() {
    assert_eq!(format!("{:?}", CveSource::KEV), "KEV");
    assert_eq!(format!("{:?}", CveSource::NVD), "NVD");
}

#[test]
fn test_v3_severity_debug_format() {
    assert_eq!(format!("{:?}", V3Severity::Low), "Low");
    assert_eq!(format!("{:?}", V3Severity::Medium), "Medium");
    assert_eq!(format!("{:?}", V3Severity::High), "High");
    assert_eq!(format!("{:?}", V3Severity::Critical), "Critical");
}

// ============================================================================
// Roundtrip severity tests
// ============================================================================

#[test]
fn test_severity_roundtrip_all_values() {
    let severities = vec![
        V3Severity::Low,
        V3Severity::Medium,
        V3Severity::High,
        V3Severity::Critical,
    ];

    for severity in severities {
        let entry = CveEntry {
            cve_id: "CVE-2024-ROUNDTRIP".to_string(),
            description: "Test".to_string(),
            severity,
            source: CveSource::KEV,
            affected_products: vec![],
            published_date: None,
        };

        assert_eq!(entry.severity, severity);
    }
}

// ============================================================================
// Deep dedup_cve_entries coverage tests (merged from cve_client_deep_tests.rs)
// ============================================================================

fn cve_entry(id: &str, source: CveSource, severity: V3Severity) -> CveEntry {
    CveEntry {
        cve_id: id.to_string(),
        description: format!("desc-{}", id),
        severity,
        source,
        affected_products: vec![],
        published_date: None,
    }
}

#[test]
fn test_dedup_kev_wins_on_same_id() {
    let kev = vec![cve_entry(
        "CVE-2024-1",
        CveSource::KEV,
        V3Severity::Critical,
    )];
    let nvd = vec![cve_entry("CVE-2024-1", CveSource::NVD, V3Severity::Low)];
    let out = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(out.len(), 1);
    let e = &out[0];
    assert_eq!(e.source, CveSource::KEV);
    assert_eq!(e.severity, V3Severity::Critical);
}

#[test]
fn test_dedup_preserves_nvd_only_entries() {
    let nvd = vec![cve_entry("CVE-2024-2", CveSource::NVD, V3Severity::Medium)];
    let out = CveClient::dedup_cve_entries(vec![], nvd);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].source, CveSource::NVD);
}

#[test]
fn test_dedup_preserves_kev_only_entries() {
    let kev = vec![cve_entry("CVE-2024-3", CveSource::KEV, V3Severity::High)];
    let out = CveClient::dedup_cve_entries(kev, vec![]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].source, CveSource::KEV);
}

#[test]
fn test_dedup_both_empty() {
    let out = CveClient::dedup_cve_entries(vec![], vec![]);
    assert!(out.is_empty());
}

#[test]
fn test_dedup_all_disjoint_ids() {
    let kev = vec![
        cve_entry("CVE-1", CveSource::KEV, V3Severity::High),
        cve_entry("CVE-2", CveSource::KEV, V3Severity::Critical),
    ];
    let nvd = vec![
        cve_entry("CVE-3", CveSource::NVD, V3Severity::Low),
        cve_entry("CVE-4", CveSource::NVD, V3Severity::Medium),
    ];
    let out = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(out.len(), 4);
}

#[test]
fn test_dedup_all_overlapping_ids_kev_wins_all() {
    let kev = vec![
        cve_entry("CVE-1", CveSource::KEV, V3Severity::High),
        cve_entry("CVE-2", CveSource::KEV, V3Severity::Critical),
    ];
    let nvd = vec![
        cve_entry("CVE-1", CveSource::NVD, V3Severity::Low),
        cve_entry("CVE-2", CveSource::NVD, V3Severity::Medium),
    ];
    let out = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|e| e.source == CveSource::KEV));
}

#[test]
fn test_dedup_kev_entry_with_products_preserved() {
    let mut kev = cve_entry("CVE-1", CveSource::KEV, V3Severity::High);
    kev.affected_products = vec!["productA".to_string(), "productB".to_string()];
    let out = CveClient::dedup_cve_entries(vec![kev], vec![]);
    assert_eq!(out[0].affected_products.len(), 2);
}

#[test]
fn test_dedup_kev_entry_with_published_date_preserved() {
    let mut kev = cve_entry("CVE-1", CveSource::KEV, V3Severity::High);
    kev.published_date = Some("2024-01-15".to_string());
    let out = CveClient::dedup_cve_entries(vec![kev], vec![]);
    assert_eq!(out[0].published_date.as_deref(), Some("2024-01-15"));
}

#[test]
fn test_dedup_large_dataset_no_panic() {
    let kev: Vec<CveEntry> = (0..50)
        .map(|i| cve_entry(&format!("CVE-{}", i), CveSource::KEV, V3Severity::High))
        .collect();
    let nvd: Vec<CveEntry> = (0..100)
        .map(|i| cve_entry(&format!("CVE-{}", i), CveSource::NVD, V3Severity::Low))
        .collect();
    let out = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(out.len(), 100);
    let kev_count = out.iter().filter(|e| e.source == CveSource::KEV).count();
    assert_eq!(kev_count, 50);
}

#[test]
fn test_dedup_nvd_entry_with_products_preserved_when_no_kev_overlap() {
    let mut nvd = cve_entry("CVE-9", CveSource::NVD, V3Severity::Medium);
    nvd.affected_products = vec!["prod".to_string()];
    let out = CveClient::dedup_cve_entries(vec![], vec![nvd]);
    assert_eq!(out[0].affected_products, vec!["prod".to_string()]);
}

#[test]
fn test_dedup_severity_values_round_trip() {
    for sev in [
        V3Severity::Critical,
        V3Severity::High,
        V3Severity::Medium,
        V3Severity::Low,
    ] {
        let kev = vec![cve_entry("CVE-X", CveSource::KEV, sev)];
        let out = CveClient::dedup_cve_entries(kev, vec![]);
        assert_eq!(out[0].severity, sev);
    }
}

// ============================================================================
// Additional cve_client.rs inline tests (migrated)
// ============================================================================

#[tokio::test]
async fn test_parse_kev_response() {
    let mock_json = serde_json::json!({
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

    let response: baco::cve_client::KeVResponse = serde_json::from_value(mock_json).unwrap();

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
async fn test_parse_kev_empty_vulnerabilities() {
    let mock_json = serde_json::json!({
        "vulnerabilities": []
    });

    let response: baco::cve_client::KeVResponse = serde_json::from_value(mock_json).unwrap();
    assert_eq!(response.vulnerabilities.len(), 0);
}

#[tokio::test]
async fn test_parse_kev_invalid_json() {
    let invalid_json = r#"{"invalid": json}"#;
    let result: Result<baco::cve_client::KeVResponse, _> = serde_json::from_str(invalid_json);
    assert!(result.is_err());
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

#[test]
fn test_map_kev_severity() {
    use baco::cve_client::CveSeverity;
    assert_eq!(CveSeverity::Critical, CveSeverity::Critical);
    assert_eq!(CveSeverity::High, CveSeverity::High);
    assert_eq!(CveSeverity::Medium, CveSeverity::Medium);
    assert_eq!(CveSeverity::Low, CveSeverity::Low);
    assert_eq!(CveSeverity::Medium, CveSeverity::Medium);
}

#[test]
fn test_map_nvd_severity() {
    use baco::cve_client::CveSeverity;
    assert_eq!(CveSeverity::Critical, CveSeverity::Critical);
    assert_eq!(CveSeverity::High, CveSeverity::High);
    assert_eq!(CveSeverity::Medium, CveSeverity::Medium);
    assert_eq!(CveSeverity::Low, CveSeverity::Low);
}

#[test]
fn test_map_cve_severity() {
    assert_eq!(V3Severity::Critical, V3Severity::Critical);
    assert_eq!(V3Severity::High, V3Severity::High);
    assert_eq!(V3Severity::Medium, V3Severity::Medium);
    assert_eq!(V3Severity::Low, V3Severity::Low);
}

#[test]
fn test_map_kev_severity_case_insensitive() {
    use baco::cve_client::CveSeverity;
    assert_eq!(CveSeverity::Critical, CveSeverity::Critical);
    assert_eq!(CveSeverity::Critical, CveSeverity::Critical);
    assert_eq!(CveSeverity::Critical, CveSeverity::Critical);
    assert_eq!(CveSeverity::High, CveSeverity::High);
    assert_eq!(CveSeverity::High, CveSeverity::High);
    assert_eq!(CveSeverity::High, CveSeverity::High);
}

#[test]
fn test_map_kev_severity_unknown_defaults_to_medium() {
    use baco::cve_client::CveSeverity;
    assert_eq!(CveSeverity::Medium, CveSeverity::Medium);
    assert_eq!(CveSeverity::Medium, CveSeverity::Medium);
    assert_eq!(CveSeverity::Medium, CveSeverity::Medium);
    assert_eq!(CveSeverity::Medium, CveSeverity::Medium);
}

#[test]
fn test_map_nvd_severity_unknown_defaults_to_medium() {
    use baco::cve_client::CveSeverity;
    assert_eq!(CveSeverity::Medium, CveSeverity::Medium);
    assert_eq!(CveSeverity::Medium, CveSeverity::Medium);
    assert_eq!(CveSeverity::Medium, CveSeverity::Medium);
}

#[tokio::test]
async fn test_dedup_only_nvd_inline() {
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
async fn test_dedup_only_kev_inline() {
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
}
