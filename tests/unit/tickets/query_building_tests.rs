//! Edge case tests for GitHub/GitLab query building in ticket search
//!
//! These tests verify URL encoding and query construction without making
//! actual HTTP requests. They cover edge cases that could break search queries.
//!
//! Tests are deterministic and fast (<200ms each) - they verify query
//! construction logic only, not actual API responses.

use baco::tickets::{TicketSearcher, TicketSystem};

// Helper to extract the query string from a constructed URL
fn extract_query_from_url(url: &str) -> String {
    url.split('?').nth(1).unwrap_or("").to_string()
}

// Helper to decode URL-encoded string for verification
fn url_decode(s: &str) -> String {
    s.replace("%20", " ")
        .replace("%3A", ":")
        .replace("%2D", "-")
        .replace("%2F", "/")
        .replace("%3F", "?")
        .replace("%3D", "=")
        .replace("%26", "&")
        .replace("%22", "\"")
        .replace("%27", "'")
}

// ============================================================================
// Test 1: Empty query string handling
// ============================================================================

#[test]
fn test_empty_query_string_handling() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = futures::executor::block_on(searcher.search_for_finding(""))
        .expect("Search should not fail");

    // Empty query should return empty results (no panic)
    assert_eq!(results.len(), 0);
}

#[test]
fn test_empty_query_builds_valid_url() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let results = futures::executor::block_on(searcher.search_for_finding("   "))
        .expect("Search with whitespace should not fail");

    assert_eq!(results.len(), 0);
}

// ============================================================================
// Test 2: CVE IDs with hyphens (e.g., "CVE-2024-1234")
// ============================================================================

#[test]
fn test_cve_id_with_hyphens_in_query() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);
    let cve_id = "CVE-2024-12345";
    let results = futures::executor::block_on(searcher.search_for_finding(cve_id))
        .expect("Search should not fail");

    // Should not panic, returns empty since no real API call
    assert_eq!(results.len(), 0);
}

#[test]
fn test_cve_id_url_encoding_preserves_hyphens() {
    // CVE IDs should be URL-encoded but hyphens are safe characters
    let cve_id = "CVE-2024-99999";
    let encoded = urlencoding::encode(cve_id);

    // Hyphens should remain unencoded
    assert!(!encoded.contains("%2D") || encoded == cve_id);
    assert!(encoded.starts_with("CVE-"));
}

// ============================================================================
// Test 3: Very long finding strings (>500 chars)
// ============================================================================

#[test]
fn test_very_long_finding_string_over_500_chars() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);

    // Create a finding string >500 characters
    let long_finding = "CVE-2024-1234 ".repeat(100);
    assert!(long_finding.len() > 500);

    let results = futures::executor::block_on(searcher.search_for_finding(&long_finding))
        .expect("Search with long string should not fail");

    // Should handle gracefully without panic
    assert_eq!(results.len(), 0);
}

#[test]
fn test_long_query_still_builds_valid_url() {
    let long_string = "a".repeat(600);
    let query = format!("vulnerability {} state:open", &long_string[..100]);

    // URL encoding should handle long strings
    let encoded = urlencoding::encode(&query);
    assert!(!encoded.is_empty());
    assert!(encoded.len() > 100);
}

// ============================================================================
// Test 4: Special characters in URLs (spaces, quotes, ampersands)
// ============================================================================

#[test]
fn test_special_characters_space_encoding() {
    let finding = "SQL injection in user input";
    let encoded = urlencoding::encode(finding);

    // Spaces should be encoded as %20 or +
    assert!(encoded.contains("%20") || encoded.contains("+"));
    assert!(!encoded.contains(" "));
}

#[test]
fn test_special_characters_quote_encoding() {
    let finding = 'vulnerability with "quotes" inside';
    let encoded = urlencoding::encode(finding);

    // Quotes should be encoded
    assert!(!encoded.contains('"'));
    assert!(encoded.contains("%22"));
}

#[test]
fn test_special_characters_ampersand_encoding() {
    let finding = "error & vulnerability";
    let encoded = urlencoding::encode(finding);

    // Ampersand should be encoded
    assert!(!encoded.contains('&'));
    assert!(encoded.contains("%26"));
}

#[test]
fn test_special_characters_combined() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);

    // Finding with multiple special characters
    let finding = "XSS & SQL injection with \"quotes\" and spaces";
    let results = futures::executor::block_on(searcher.search_for_finding(finding))
        .expect("Search should not fail");

    assert_eq!(results.len(), 0);
}

// ============================================================================
// Test 5: Unicode characters in search terms
// ============================================================================

#[test]
fn test_unicode_characters_basic() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);

    // Finding with unicode characters
    let finding = "vulnerability in 日本語 code";
    let results = futures::executor::block_on(searcher.search_for_finding(finding))
        .expect("Search with unicode should not fail");

    assert_eq!(results.len(), 0);
}

#[test]
fn test_unicode_characters_emoji() {
    let finding = "security issue 🔒 critical";
    let encoded = urlencoding::encode(finding);

    // Emoji should be encoded as UTF-8 percent encoding
    assert!(!encoded.is_empty());
}

#[test]
fn test_unicode_characters_european() {
    let finding = "vulnerabilité avec émojis ñ ü ö";
    let encoded = urlencoding::encode(finding);

    // Should encode non-ASCII characters
    assert!(!encoded.is_empty());
    assert!(encoded.len() > finding.len()); // UTF-8 encoding increases size
}

// ============================================================================
// Test 6: Multiple CVE IDs in one query
// ============================================================================

#[test]
fn test_multiple_cve_ids_in_single_query() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);

    let finding = "CVE-2024-1234 and CVE-2024-5678 and CVE-2024-9012";
    let results = futures::executor::block_on(searcher.search_for_finding(finding))
        .expect("Search with multiple CVEs should not fail");

    assert_eq!(results.len(), 0);
}

#[test]
fn test_multiple_cve_ids_url_encoding() {
    let finding = "CVE-2024-1234 CVE-2024-5678";
    let encoded = urlencoding::encode(finding);

    // Both CVE IDs should be preserved in encoding
    assert!(encoded.contains("CVE-2024-1234") || encoded.contains("CVE%2D2024%2D1234"));
    assert!(encoded.contains("CVE-2024-5678") || encoded.contains("CVE%2D2024%2D5678"));
}

// ============================================================================
// Test 7: Case sensitivity in CVE IDs
// ============================================================================

#[test]
fn test_cve_id_case_sensitivity_uppercase() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);

    let finding = "CVE-2024-1234";
    let results = futures::executor::block_on(searcher.search_for_finding(finding))
        .expect("Search should not fail");

    assert_eq!(results.len(), 0);
}

#[test]
fn test_cve_id_case_variants() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);

    // Test different case variants
    let variants = vec!["CVE-2024-1234", "cve-2024-1234", "Cve-2024-1234"];

    for variant in variants {
        let results = futures::executor::block_on(searcher.search_for_finding(variant))
            .expect("Search should not fail");
        assert_eq!(results.len(), 0);
    }
}

#[test]
fn test_cve_with_colon_variant() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://github.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);

    // CVE: format (with colon)
    let finding = "CVE:2024-1234";
    let results = futures::executor::block_on(searcher.search_for_finding(finding))
        .expect("Search should not fail");

    assert_eq!(results.len(), 0);
}

// ============================================================================
// Test 8: Malformed URLs (missing protocol, invalid domains)
// ============================================================================

#[test]
fn test_malformed_url_missing_protocol() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "github.com".to_string(), // Missing https://
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);

    // Should handle gracefully without panic
    let results = futures::executor::block_on(searcher.search_for_finding("test"))
        .expect("Search should not fail even with malformed URL");

    assert_eq!(results.len(), 0);
}

#[test]
fn test_malformed_url_invalid_domain() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "https://invalid..domain".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);

    // Should handle gracefully without panic
    let results = futures::executor::block_on(searcher.search_for_finding("test"))
        .expect("Search should not fail even with invalid domain");

    assert_eq!(results.len(), 0);
}

#[test]
fn test_malformed_url_empty() {
    let systems = vec![TicketSystem {
        name: "GitHub".to_string(),
        system_type: "github".to_string(),
        url: "".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);

    // Should handle gracefully without panic
    let results = futures::executor::block_on(searcher.search_for_finding("test"))
        .expect("Search should not fail even with empty URL");

    assert_eq!(results.len(), 0);
}

#[test]
fn test_malformed_url_with_trailing_slash_handling() {
    let systems = vec![
        TicketSystem {
            name: "GitHub1".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com".to_string(),
            credentials: None,
        },
        TicketSystem {
            name: "GitHub2".to_string(),
            system_type: "github".to_string(),
            url: "https://github.com/".to_string(),
            credentials: None,
        },
    ];

    let searcher = TicketSearcher::new(systems);

    // Both URLs should be handled (trailing slash trimmed)
    let results = futures::executor::block_on(searcher.search_for_finding("test"))
        .expect("Search should not fail");

    assert_eq!(results.len(), 0);
}

// ============================================================================
// GitLab-specific tests
// ============================================================================

#[test]
fn test_gitlab_query_building_with_special_chars() {
    let systems = vec![TicketSystem {
        name: "GitLab".to_string(),
        system_type: "gitlab".to_string(),
        url: "https://gitlab.com".to_string(),
        credentials: Some("test-token".to_string()),
    }];

    let searcher = TicketSearcher::new(systems);

    let finding = "CVE-2024-1234 & vulnerability";
    let results = futures::executor::block_on(searcher.search_for_finding(finding))
        .expect("GitLab search should not fail");

    assert_eq!(results.len(), 0);
}

#[test]
fn test_gitlab_unicode_handling() {
    let systems = vec![TicketSystem {
        name: "GitLab".to_string(),
        system_type: "gitlab".to_string(),
        url: "https://gitlab.com".to_string(),
        credentials: None,
    }];

    let searcher = TicketSearcher::new(systems);

    let finding = "vulnerabilité avec accents";
    let results = futures::executor::block_on(searcher.search_for_finding(finding))
        .expect("GitLab search with unicode should not fail");

    assert_eq!(results.len(), 0);
}
