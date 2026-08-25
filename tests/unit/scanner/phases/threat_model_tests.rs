//! Unit tests for threat modeling phase.
//!
//! Tests threat model generation, STRIDE classification, and edge cases.

use baco::threat_model::generation::{
    generate_threat_model_static, load_or_generate_architecture, save_to_context,
};
use baco::threat_model::{
    generate_threat_model_static, generate_threat_model_with_llm, load_or_generate_architecture,
    save_to_context, ThreatModelFile, ThreatModelFrontmatter,
};

// ============================================================================
// ThreatModelFile Tests
// ============================================================================

#[test]
fn test_threat_model_file_default() {
    let model = ThreatModelFile::default();

    assert_eq!(model.frontmatter.version, "1.0");
    assert_eq!(model.frontmatter.project_type, "unknown");
    assert_eq!(model.frontmatter.total_threats, 0);
    assert!(model.frontmatter.high_risk_areas.is_empty());
}

#[test]
fn test_threat_model_frontmatter_default() {
    let frontmatter = ThreatModelFrontmatter::default();

    assert_eq!(frontmatter.version, "1.0");
    assert!(!frontmatter.generated_at.is_empty());
    assert_eq!(frontmatter.project_type, "unknown");
    assert_eq!(frontmatter.total_threats, 0);
}

// ============================================================================
// generate_threat_model_static Tests
// ============================================================================

#[test]
fn test_threat_model_basic() {
    let architecture = "HTTP + database + file system";
    let threat_model = generate_threat_model_static(architecture);

    assert!(threat_model.contains("=== THREAT MODEL: STRIDE Analysis ==="));
    assert!(threat_model.contains("### 1. TRUST BOUNDARIES"));
    assert!(threat_model.contains("### 2. DATA FLOWS"));
    assert!(threat_model.contains("### 3. ATTACK SURFACES"));
    assert!(threat_model.contains("### 4. STRIDE THREATS"));
}

#[test]
fn test_threat_model_empty_input() {
    let threat_model = generate_threat_model_static("");

    assert!(threat_model.contains("TRUST BOUNDARIES"));
    assert!(!threat_model.is_empty());
}

#[test]
fn test_threat_model_whitespace_only() {
    let threat_model = generate_threat_model_static("   \n\n   ");

    assert!(threat_model.contains("TRUST BOUNDARIES"));
    assert!(!threat_model.is_empty());
}

#[test]
fn test_threat_model_api_detected() {
    let threat_model = generate_threat_model_static("HTTP API enabled");

    assert!(threat_model.contains("**External Interface**: HTTP/HTTPS API"));
    assert!(threat_model.contains("Entry points: All HTTP endpoints"));
    assert!(threat_model.contains("Risks: Request forgery, header injection, SSRF"));
}

#[test]
fn test_threat_model_database_detected() {
    let threat_model = generate_threat_model_static("database: PostgreSQL");

    assert!(threat_model.contains("**Data Store**: Database connection"));
    assert!(threat_model.contains("Access: Application service layer"));
    assert!(threat_model.contains("Risks: SQL injection, privilege escalation, data exfiltration"));
}

#[test]
fn test_threat_model_filesystem_detected() {
    let threat_model = generate_threat_model_static("file system: User uploads");

    assert!(threat_model.contains("**File System**: Local storage"));
    assert!(threat_model.contains("Access: File upload, configuration loading"));
    assert!(threat_model.contains("Risks: Path traversal, arbitrary file read/write"));
}

#[test]
fn test_threat_model_no_database() {
    let threat_model = generate_threat_model_static("No database");

    assert!(!threat_model.contains("**Data Store**: Database connection"));
    assert!(!threat_model.contains("SQL injection"));
}

#[test]
fn test_threat_model_no_filesystem() {
    let threat_model = generate_threat_model_static("No file system");

    assert!(!threat_model.contains("**File System**: Local storage"));
    assert!(!threat_model.contains("Path traversal"));
}

#[test]
fn test_threat_model_data_flows_api() {
    let threat_model = generate_threat_model_static("HTTP API enabled");

    assert!(threat_model.contains("User Request -> API Endpoint -> Validation"));
    assert!(threat_model.contains("Sensitive in transit: Consider TLS enforcement"));
    assert!(threat_model.contains("Sensitive at rest: Consider encryption"));
}

#[test]
fn test_threat_model_data_flows_database() {
    let threat_model = generate_threat_model_static("database: MySQL");

    assert!(threat_model.contains("Application Write -> Database"));
    assert!(threat_model.contains("Sensitive data: PII, credentials, session tokens"));
}

#[test]
fn test_stride_spoofing_section() {
    let threat_model = generate_threat_model_static("Full stack");

    assert!(threat_model.contains("#### S - Spoofing"));
    assert!(threat_model.contains("Authentication bypass"));
    assert!(threat_model.contains("session token manipulation"));
    assert!(threat_model.contains("**Recommendation**: Implement strong auth"));
}

#[test]
fn test_stride_tampering_section() {
    let threat_model = generate_threat_model_static("Full stack");

    assert!(threat_model.contains("#### T - Tampering"));
    assert!(threat_model.contains("Input validation bypass"));
    assert!(threat_model.contains("injection attacks"));
    assert!(threat_model.contains("**Recommendation**: Input sanitization"));
}

#[test]
fn test_stride_repudiation_section() {
    let threat_model = generate_threat_model_static("Any architecture");

    assert!(threat_model.contains("#### R - Repudiation"));
    assert!(threat_model.contains("Lack of audit logging"));
    assert!(threat_model.contains("**Recommendation**: Comprehensive logging"));
}

#[test]
fn test_stride_information_disclosure_section() {
    let threat_model = generate_threat_model_static("Full stack");

    assert!(threat_model.contains("#### I - Information Disclosure"));
    assert!(threat_model.contains("Sensitive data in logs or error messages"));
    assert!(threat_model.contains("**Recommendation**: Log sanitization"));
}

#[test]
fn test_stride_denial_of_service_section() {
    let threat_model = generate_threat_model_static("Full stack");

    assert!(threat_model.contains("#### D - Denial of Service"));
    assert!(threat_model.contains("Resource exhaustion"));
    assert!(threat_model.contains("**Recommendation**: Rate limiting"));
}

#[test]
fn test_stride_elevation_of_privilege_section() {
    let threat_model = generate_threat_model_static("Any architecture");

    assert!(threat_model.contains("#### E - Elevation of Privilege"));
    assert!(threat_model.contains("Insufficient authorization checks"));
    assert!(threat_model.contains("Vertical privilege escalation"));
    assert!(threat_model.contains("**Recommendation**: Role-based access control"));
}

#[test]
fn test_threat_model_all_stride_letters() {
    let threat_model = generate_threat_model_static("Full stack");

    assert!(threat_model.contains("#### S - Spoofing"));
    assert!(threat_model.contains("#### T - Tampering"));
    assert!(threat_model.contains("#### R - Repudiation"));
    assert!(threat_model.contains("#### I - Information Disclosure"));
    assert!(threat_model.contains("#### D - Denial of Service"));
    assert!(threat_model.contains("#### E - Elevation of Privilege"));
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_threat_model_special_characters() {
    let threat_model = generate_threat_model_static(r#"Special: <script>alert('xss')</script>"#);

    assert!(threat_model.contains("TRUST BOUNDARIES"));
    assert!(!threat_model.is_empty());
}

#[test]
fn test_threat_model_unicode_input() {
    let threat_model = generate_threat_model_static("café naïve résumé");

    assert!(threat_model.contains("TRUST BOUNDARIES"));
    assert!(!threat_model.is_empty());
}

#[test]
fn test_threat_model_very_long_input() {
    let long_input = "A".repeat(50000);
    let threat_model = generate_threat_model_static(&long_input);

    assert!(threat_model.contains("TRUST BOUNDARIES"));
    assert!(!threat_model.is_empty());
}

#[test]
fn test_threat_model_case_insensitive_detection() {
    let test_cases = vec![
        "HTTP endpoint",
        "http endpoint",
        "Http Endpoint",
        "DATABASE: postgres",
        "database: postgres",
        "File System: uploads",
        "file system: uploads",
    ];

    for arch in test_cases {
        let threat_model = generate_threat_model_static(arch);
        assert!(
            threat_model.contains("TRUST BOUNDARIES"),
            "Failed for: {}",
            arch
        );
    }
}

#[test]
fn test_threat_model_combined_components() {
    let threat_model = generate_threat_model_static("HTTP + database + file system");

    assert!(threat_model.contains("HTTP/HTTPS API"));
    assert!(threat_model.contains("Database connection"));
    assert!(threat_model.contains("File System"));
}

#[test]
fn test_threat_model_all_recommendations_present() {
    let threat_model = generate_threat_model_static("full stack");

    assert!(threat_model.contains("Recommendation"));
    assert!(threat_model.contains("strong auth"));
    assert!(threat_model.contains("Input sanitization"));
    assert!(threat_model.contains("Comprehensive logging"));
    assert!(threat_model.contains("Log sanitization"));
    assert!(threat_model.contains("Rate limiting"));
    assert!(threat_model.contains("Role-based access control"));
}

// ============================================================================
// Performance Tests
// ============================================================================

#[test]
fn test_performance_small_architecture() {
    let start = std::time::Instant::now();

    for _ in 0..100 {
        let _ = generate_threat_model_static("Small");
    }

    let duration = start.elapsed();
    assert!(
        duration.as_millis() < 1000,
        "Should complete 100 iterations in under 1 second"
    );
}

#[test]
fn test_performance_large_architecture() {
    let large_arch = "A".repeat(10000);
    let start = std::time::Instant::now();

    for _ in 0..10 {
        let _ = generate_threat_model_static(&large_arch);
    }

    let duration = start.elapsed();
    assert!(
        duration.as_millis() < 5000,
        "Should complete 10 iterations with large input in under 5 seconds"
    );
}
