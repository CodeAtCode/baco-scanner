//! Deep dedup_cve_entries coverage for cve_client.rs
//!
//! The HTTP fetch functions hit real CISA/NVD endpoints and cannot be
//! unit-tested without network. These tests focus on dedup_cve_entries
//! edge cases to push coverage on the pure-logic path.

use baco::cve_client::CveClient;
use baco::scanner_types::cve::{CveEntry, CveSource};
use baco::scanner_types::severity::V3Severity;

fn entry(id: &str, source: CveSource, severity: V3Severity) -> CveEntry {
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
fn dedup_kev_wins_on_same_id() {
    let kev = vec![entry("CVE-2024-1", CveSource::KEV, V3Severity::Critical)];
    let nvd = vec![entry("CVE-2024-1", CveSource::NVD, V3Severity::Low)];
    let out = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(out.len(), 1);
    let e = &out[0];
    assert_eq!(e.source, CveSource::KEV);
    assert_eq!(e.severity, V3Severity::Critical);
}

#[test]
fn dedup_preserves_nvd_only_entries() {
    let nvd = vec![entry("CVE-2024-2", CveSource::NVD, V3Severity::Medium)];
    let out = CveClient::dedup_cve_entries(vec![], nvd);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].source, CveSource::NVD);
}

#[test]
fn dedup_preserves_kev_only_entries() {
    let kev = vec![entry("CVE-2024-3", CveSource::KEV, V3Severity::High)];
    let out = CveClient::dedup_cve_entries(kev, vec![]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].source, CveSource::KEV);
}

#[test]
fn dedup_both_empty() {
    let out = CveClient::dedup_cve_entries(vec![], vec![]);
    assert!(out.is_empty());
}

#[test]
fn dedup_all_disjoint_ids() {
    let kev = vec![
        entry("CVE-1", CveSource::KEV, V3Severity::High),
        entry("CVE-2", CveSource::KEV, V3Severity::Critical),
    ];
    let nvd = vec![
        entry("CVE-3", CveSource::NVD, V3Severity::Low),
        entry("CVE-4", CveSource::NVD, V3Severity::Medium),
    ];
    let out = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(out.len(), 4);
}

#[test]
fn dedup_all_overlapping_ids_kev_wins_all() {
    let kev = vec![
        entry("CVE-1", CveSource::KEV, V3Severity::High),
        entry("CVE-2", CveSource::KEV, V3Severity::Critical),
    ];
    let nvd = vec![
        entry("CVE-1", CveSource::NVD, V3Severity::Low),
        entry("CVE-2", CveSource::NVD, V3Severity::Medium),
    ];
    let out = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|e| e.source == CveSource::KEV));
}

#[test]
fn dedup_kev_entry_with_products_preserved() {
    let mut kev = entry("CVE-1", CveSource::KEV, V3Severity::High);
    kev.affected_products = vec!["productA".to_string(), "productB".to_string()];
    let out = CveClient::dedup_cve_entries(vec![kev], vec![]);
    assert_eq!(out[0].affected_products.len(), 2);
}

#[test]
fn dedup_kev_entry_with_published_date_preserved() {
    let mut kev = entry("CVE-1", CveSource::KEV, V3Severity::High);
    kev.published_date = Some("2024-01-15".to_string());
    let out = CveClient::dedup_cve_entries(vec![kev], vec![]);
    assert_eq!(out[0].published_date.as_deref(), Some("2024-01-15"));
}

#[test]
fn dedup_large_dataset_no_panic() {
    let kev: Vec<CveEntry> = (0..50)
        .map(|i| entry(&format!("CVE-{}", i), CveSource::KEV, V3Severity::High))
        .collect();
    let nvd: Vec<CveEntry> = (0..100)
        .map(|i| entry(&format!("CVE-{}", i), CveSource::NVD, V3Severity::Low))
        .collect();
    let out = CveClient::dedup_cve_entries(kev, nvd);
    assert_eq!(out.len(), 100);
    let kev_count = out.iter().filter(|e| e.source == CveSource::KEV).count();
    assert_eq!(kev_count, 50);
}

#[test]
fn dedup_nvd_entry_with_products_preserved_when_no_kev_overlap() {
    let mut nvd = entry("CVE-9", CveSource::NVD, V3Severity::Medium);
    nvd.affected_products = vec!["prod".to_string()];
    let out = CveClient::dedup_cve_entries(vec![], vec![nvd]);
    assert_eq!(out[0].affected_products, vec!["prod".to_string()]);
}

#[test]
fn dedup_severity_values_round_trip() {
    for sev in [
        V3Severity::Critical,
        V3Severity::High,
        V3Severity::Medium,
        V3Severity::Low,
    ] {
        let kev = vec![entry("CVE-X", CveSource::KEV, sev)];
        let out = CveClient::dedup_cve_entries(kev, vec![]);
        assert_eq!(out[0].severity, sev);
    }
}
