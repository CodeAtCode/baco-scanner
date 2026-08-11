//! Unit tests for src/threat_model.rs
//!
//! Covers:
//! - ThreatModelingPhase::run
//! - load_or_generate_architecture
//! - generate_threat_model_static
//! - ThreatModelingPhase::generate_threat_model_with_llm (mocked)
//! - save_to_context
//! - STRIDE threat generation
//! - Trust boundaries detection
//! - Edge cases and error handling

use crate::fixtures::make_threat_model_test_context;
use baco::analysis_context::AnalysisContext;
use baco::threat_model::*;
use tempfile::tempdir;

// ============================================================================
// LOAD OR GENERATE ARCHITECTURE TESTS
// ============================================================================

#[test]
fn test_load_or_generate_architecture_with_existing_summary() {
    let tmp = tempdir().unwrap();
    let ctx = AnalysisContext {
        project_type: baco::project_type::ProjectType::Web,
        architecture_summary: "Existing architecture with HTTP and database".to_string(),
        threat_model: None,
        invariants: Vec::new(),
        findings_so_far: Vec::new(),
    };
    ctx.save(tmp.path()).unwrap();

    let result = load_or_generate_architecture(tmp.path(), &ctx);

    assert_eq!(result, "Existing architecture with HTTP and database");
}

#[test]
fn test_load_or_generate_architecture_with_empty_summary() {
    let tmp = tempdir().unwrap();

    // Create a simple Rust file for detection
    let src_dir = tmp.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("main.rs"), "fn main() {}").unwrap();

    let ctx = AnalysisContext {
        project_type: baco::project_type::ProjectType::CLI,
        architecture_summary: String::new(),
        threat_model: None,
        invariants: Vec::new(),
        findings_so_far: Vec::new(),
    };
    ctx.save(tmp.path()).unwrap();

    let result = load_or_generate_architecture(tmp.path(), &ctx);

    // Should generate architecture summary, not return placeholder
    assert!(result.contains("ARCHITECTURAL SUMMARY"));
    assert!(result.contains("Project type"));
    assert_ne!(result, "No architecture summary available");
}

#[test]
fn test_load_or_generate_architecture_with_whitespace_only() {
    let tmp = tempdir().unwrap();
    let ctx = AnalysisContext {
        project_type: baco::project_type::ProjectType::Library,
        architecture_summary: "   \n\n   ".to_string(),
        threat_model: None,
        invariants: Vec::new(),
        findings_so_far: Vec::new(),
    };
    ctx.save(tmp.path()).unwrap();

    let result = load_or_generate_architecture(tmp.path(), &ctx);

    // Non-empty string with whitespace is used as-is
    assert_eq!(result, "   \n\n   ");
}

// ============================================================================
// SAVE TO CONTEXT TESTS
// ============================================================================

#[test]
fn test_save_to_context_creates_threat_model() {
    let tmp = tempdir().unwrap();
    let threat_model = "Test threat model content";

    save_to_context(tmp.path(), threat_model);

    let loaded = AnalysisContext::load(tmp.path()).unwrap();
    assert!(loaded.threat_model.is_some());
    assert_eq!(loaded.threat_model.as_ref().unwrap(), threat_model);
}

#[test]
fn test_save_to_context_overwrites_existing() {
    let tmp = tempdir().unwrap();

    // Create initial context with threat model
    let ctx = AnalysisContext {
        project_type: baco::project_type::ProjectType::Web,
        architecture_summary: "Old arch".to_string(),
        threat_model: Some("Old threat model".to_string()),
        invariants: Vec::new(),
        findings_so_far: Vec::new(),
    };
    ctx.save(tmp.path()).unwrap();

    // Save new threat model
    save_to_context(tmp.path(), "New threat model");

    let loaded = AnalysisContext::load(tmp.path()).unwrap();
    assert_eq!(loaded.threat_model.as_ref().unwrap(), "New threat model");
}

// ============================================================================
// RUN METHOD TESTS
// ============================================================================

#[tokio::test]
async fn test_run_with_valid_context() {
    let tmp = tempdir().unwrap();
    let ctx = AnalysisContext {
        project_type: baco::project_type::ProjectType::Web,
        architecture_summary: "HTTP API with PostgreSQL database".to_string(),
        threat_model: None,
        invariants: Vec::new(),
        findings_so_far: Vec::new(),
    };
    ctx.save(tmp.path()).unwrap();

    let result = ThreatModelingPhase::run(tmp.path(), &ctx, None).await;

    assert!(result.is_ok());
    let threat_model = result.unwrap();
    assert!(threat_model.contains("STRIDE"));
    assert!(threat_model.contains("TRUST BOUNDARIES"));
}

#[tokio::test]
async fn test_run_with_empty_context() {
    let tmp = tempdir().unwrap();
    let ctx = AnalysisContext::default();

    let result = ThreatModelingPhase::run(tmp.path(), &ctx, None).await;

    assert!(result.is_ok());
    let threat_model = result.unwrap();
    assert!(threat_model.contains("STRIDE"));
}

#[tokio::test]
async fn test_run_creates_context_if_missing() {
    let tmp = tempdir().unwrap();
    let ctx = make_threat_model_test_context();

    let _ = ThreatModelingPhase::run(tmp.path(), &ctx, None)
        .await
        .unwrap();

    let loaded = AnalysisContext::load(tmp.path()).unwrap();
    assert!(loaded.threat_model.is_some());
}

// ============================================================================
// STATIC GENERATION COMPREHENSIVE TESTS
// ============================================================================

#[test]
fn test_static_generation_full_stack() {
    let architecture =
        "Full stack web application with HTTP API, PostgreSQL database, and file uploads";
    let threat_model = generate_threat_model_static(architecture);

    // Should contain all major sections
    assert!(threat_model.contains("=== THREAT MODEL: STRIDE Analysis ==="));
    assert!(threat_model.contains("### 1. TRUST BOUNDARIES"));
    assert!(threat_model.contains("### 2. DATA FLOWS"));
    assert!(threat_model.contains("### 3. ATTACK SURFACES"));
    assert!(threat_model.contains("### 4. STRIDE THREATS"));

    // Should detect all components
    assert!(threat_model.contains("HTTP/HTTPS API"));
    assert!(threat_model.contains("Database connection"));
    assert!(threat_model.contains("File System"));

    // Should contain all STRIDE categories
    assert!(threat_model.contains("#### S - Spoofing"));
    assert!(threat_model.contains("#### T - Tampering"));
    assert!(threat_model.contains("#### R - Repudiation"));
    assert!(threat_model.contains("#### I - Information Disclosure"));
    assert!(threat_model.contains("#### D - Denial of Service"));
    assert!(threat_model.contains("#### E - Elevation of Privilege"));
}

#[test]
fn test_static_generation_cli_tool() {
    let architecture = "CLI tool with file system access, no network, no database";
    let threat_model = generate_threat_model_static(architecture);

    // Should not contain API-related threats
    assert!(!threat_model.contains("HTTP/HTTPS API"));
    assert!(!threat_model.contains("API key forgery"));
    assert!(!threat_model.contains("SQL injection"));

    // Should contain file system threats
    assert!(threat_model.contains("File System"));
    assert!(threat_model.contains("Path traversal"));
}

#[test]
fn test_static_generation_library_only() {
    let architecture = "Pure Rust library with no external dependencies";
    let threat_model = generate_threat_model_static(architecture);

    // Minimal threat model for pure library
    assert!(threat_model.contains("TRUST BOUNDARIES"));
    assert!(threat_model.contains("STRIDE"));
    assert!(!threat_model.contains("HTTP/HTTPS API"));
    assert!(!threat_model.contains("Database connection"));
    assert!(!threat_model.contains("File System"));
}

// ============================================================================
// COMPONENT DETECTION EDGE CASES
// ============================================================================

#[test]
fn test_database_detection_variations() {
    let test_cases = vec![
        ("PostgreSQL database", true),
        ("mysql connected", true),
        ("sqlite file", true),
        ("data store: Redis", true),
        ("No database", false),
        ("no database", false),
        ("No DB", false),
        ("no DB", false),
        ("database backup only", true), // Contains "database" without negation
    ];

    for (arch, should_detect) in test_cases {
        let threat_model = generate_threat_model_static(arch);
        let has_db_threats = threat_model.contains("SQL injection");
        assert_eq!(has_db_threats, should_detect, "Failed for: {}", arch);
    }
}

#[test]
fn test_api_detection_variations() {
    let test_cases = vec![
        ("HTTP endpoint", true),
        ("REST API", true),
        ("router configured", true),
        ("API gateway", true),
        ("No HTTP", true), // "HTTP" still matches
        ("batch processor", false),
    ];

    for (arch, should_detect) in test_cases {
        let threat_model = generate_threat_model_static(arch);
        let has_api = threat_model.contains("HTTP/HTTPS API");
        assert_eq!(has_api, should_detect, "Failed for: {}", arch);
    }
}

#[test]
fn test_filesystem_detection_variations() {
    let test_cases = vec![
        ("file system access", true),
        ("file upload enabled", true),
        ("filesystem configured", true),
        ("No file system", false),
        ("no filesystem", false),
        ("No filesystem access", false),
        ("no filesystem access", false),
    ];

    for (arch, should_detect) in test_cases {
        let threat_model = generate_threat_model_static(arch);
        let has_fs = threat_model.contains("File System");
        assert_eq!(has_fs, should_detect, "Failed for: {}", arch);
    }
}

// ============================================================================
// DATA FLOW TESTS
// ============================================================================

#[test]
fn test_data_flows_with_api_only() {
    let architecture = "HTTP API endpoints only";
    let threat_model = generate_threat_model_static(architecture);

    assert!(threat_model.contains("User Request -> API Endpoint -> Validation"));
    assert!(threat_model.contains("Sensitive in transit"));
    assert!(!threat_model.contains("Application Write -> Database"));
}

#[test]
fn test_data_flows_with_database_only() {
    let architecture = "Database: postgresql\nData persistence layer";
    let threat_model = generate_threat_model_static(architecture);

    assert!(threat_model.contains("Application Write -> Database"));
    assert!(threat_model.contains("Sensitive data: PII, credentials, session tokens"));
}

#[test]
fn test_data_flows_combined() {
    let architecture = "HTTP + database + file system";
    let threat_model = generate_threat_model_static(architecture);

    assert!(threat_model.contains("User Request -> API Endpoint"));
    assert!(threat_model.contains("Application Write -> Database"));
    assert!(threat_model.contains("Sensitive in transit"));
    assert!(threat_model.contains("Sensitive at rest"));
}

// ============================================================================
// ATTACK SURFACE TESTS
// ============================================================================

#[test]
fn test_attack_surfaces_comprehensive() {
    let architecture = "HTTP API with database and file uploads";
    let threat_model = generate_threat_model_static(architecture);

    assert!(threat_model.contains("**HTTP Endpoints**: All routes are potential entry points"));
    assert!(threat_model.contains("**File System**: Upload directories, config files, temp files"));
    assert!(threat_model.contains("**Database**: Direct access points, backup exposure"));
}

#[test]
fn test_attack_surfaces_minimal() {
    let architecture = "Standalone application";
    let threat_model = generate_threat_model_static(architecture);

    assert!(threat_model.contains("**HTTP Endpoints**: All routes are potential entry points"));
    assert!(!threat_model.contains("**File System**"));
    assert!(!threat_model.contains("**Database**"));
}

// ============================================================================
// STRIDE SECTION TESTS
// ============================================================================

#[test]
fn test_stride_spoofing_comprehensive() {
    let threat_model = generate_threat_model_static("Full stack");

    let spoofing = threat_model.split("#### S - Spoofing").nth(1).unwrap();
    assert!(spoofing.contains("Authentication bypass"));
    assert!(spoofing.contains("session token manipulation"));
    assert!(spoofing.contains("Recommendation"));
}

#[test]
fn test_stride_tampering_with_all_components() {
    let architecture = "HTTP + database + file system";
    let threat_model = generate_threat_model_static(architecture);

    let tampering = threat_model.split("#### T - Tampering").nth(1).unwrap();
    assert!(tampering.contains("SQL injection"));
    assert!(tampering.contains("Path traversal"));
    assert!(tampering.contains("Input validation bypass"));
}

#[test]
fn test_stride_repudiation_always_present() {
    let threat_model = generate_threat_model_static("Any architecture");

    let repudiation = threat_model.split("#### R - Repudiation").nth(1).unwrap();
    assert!(repudiation.contains("Lack of audit logging"));
    assert!(repudiation.contains("Session tokens not bound"));
    assert!(repudiation.contains("Comprehensive logging"));
}

#[test]
fn test_stride_information_disclosure_comprehensive() {
    let architecture = "HTTP + file system";
    let threat_model = generate_threat_model_static(architecture);

    let id = threat_model
        .split("#### I - Information Disclosure")
        .nth(1)
        .unwrap();
    assert!(id.contains("Sensitive data in logs"));
    assert!(id.contains("Insecure storage"));
    assert!(id.contains("Config files with secrets"));
}

#[test]
fn test_stride_dos_with_all_vectors() {
    let architecture = "HTTP API + file uploads";
    let threat_model = generate_threat_model_static(architecture);

    let dos = threat_model
        .split("#### D - Denial of Service")
        .nth(1)
        .unwrap();
    assert!(dos.contains("Resource exhaustion"));
    assert!(dos.contains("API endpoint overload"));
    assert!(dos.contains("Disk fill via unbounded file uploads"));
}

#[test]
fn test_stride_elevation_always_present() {
    let threat_model = generate_threat_model_static("Any");

    let eop = threat_model
        .split("#### E - Elevation of Privilege")
        .nth(1)
        .unwrap();
    assert!(eop.contains("Insufficient authorization"));
    assert!(eop.contains("Vertical privilege escalation"));
    assert!(eop.contains("Horizontal privilege escalation"));
    assert!(eop.contains("Role-based access control"));
}

// ============================================================================
// EDGE CASES AND SPECIAL INPUTS
// ============================================================================

#[test]
fn test_special_characters_in_architecture() {
    let architecture = r#"Special: <script>alert('xss')</script> & "quotes"'s"#;
    let threat_model = generate_threat_model_static(architecture);

    assert!(threat_model.contains("TRUST BOUNDARIES"));
    assert!(!threat_model.is_empty());
}

#[test]
fn test_unicode_in_architecture() {
    let architecture = "日本語のアーキテクチャ\nÉmojis: 🔒🔑🛡️";
    let threat_model = generate_threat_model_static(architecture);

    assert!(threat_model.contains("TRUST BOUNDARIES"));
}

#[test]
fn test_very_long_architecture() {
    let architecture = format!(
        "{}\nDatabase: postgresql\n{}",
        "A".repeat(50000),
        "B".repeat(50000)
    );
    let threat_model = generate_threat_model_static(&architecture);

    assert!(threat_model.contains("SQL injection"));
    assert!(threat_model.len() > 1000);
}

#[test]
fn test_newline_variations() {
    let test_cases = vec![
        "Line1\nLine2\nLine3",
        "Line1\r\nLine2\r\nLine3",
        "Line1\rLine2\rLine3",
        "Mixed\n\r\n\rcontent",
    ];

    for architecture in test_cases {
        let threat_model = generate_threat_model_static(architecture);
        assert!(
            threat_model.contains("TRUST BOUNDARIES"),
            "Failed for: {:?}",
            architecture
        );
    }
}

#[test]
fn test_multiple_database_mentions() {
    let architecture = "postgresql primary, mysql backup, sqlite cache";
    let threat_model = generate_threat_model_static(architecture);

    assert!(threat_model.contains("SQL injection"));
    assert!(threat_model.contains("Database connection"));
}

#[test]
fn test_mixed_case_keywords() {
    let architecture = "hTtP eNdPoInTs\nDaTaBaSe: SQL\nFiLe SyStEm";
    let threat_model = generate_threat_model_static(architecture);

    // HTTP is case-sensitive in detection
    assert!(threat_model.contains("TRUST BOUNDARIES"));
}

// ============================================================================
// OUTPUT FORMAT VALIDATION
// ============================================================================

#[test]
fn test_output_markdown_structure() {
    let threat_model = generate_threat_model_static("Full stack");

    assert!(threat_model.starts_with("=== THREAT MODEL:"));
    assert!(threat_model.contains("### 1."));
    assert!(threat_model.contains("### 2."));
    assert!(threat_model.contains("### 3."));
    assert!(threat_model.contains("### 4."));
    assert!(threat_model.contains("#### S -"));
    assert!(threat_model.contains("#### T -"));
    assert!(threat_model.contains("#### R -"));
    assert!(threat_model.contains("#### I -"));
    assert!(threat_model.contains("#### D -"));
    assert!(threat_model.contains("#### E -"));
}

#[test]
fn test_output_contains_recommendations() {
    let threat_model = generate_threat_model_static("Full stack");

    assert!(threat_model.contains("**Recommendation**: Implement strong auth"));
    assert!(threat_model.contains("**Recommendation**: Input sanitization"));
    assert!(threat_model.contains("**Recommendation**: Comprehensive logging"));
    assert!(threat_model.contains("**Recommendation**: Log sanitization"));
    assert!(threat_model.contains("**Recommendation**: Rate limiting"));
    assert!(threat_model.contains("**Recommendation**: Role-based access control"));
}

#[test]
fn test_output_line_count() {
    let threat_model = generate_threat_model_static("Full stack");
    let line_count = threat_model.lines().count();

    assert!(
        line_count > 30,
        "Expected more than 30 lines, got {}",
        line_count
    );
}

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

#[test]
fn test_performance_small_input() {
    let start = std::time::Instant::now();

    for _ in 0..100 {
        let _ = generate_threat_model_static("Small");
    }

    let duration = start.elapsed();
    assert!(
        duration.as_millis() < 500,
        "100 iterations took {}ms",
        duration.as_millis()
    );
}

#[test]
fn test_performance_medium_input() {
    let arch = "HTTP + database + file system + authentication + logging";
    let start = std::time::Instant::now();

    for _ in 0..50 {
        let _ = generate_threat_model_static(arch);
    }

    let duration = start.elapsed();
    assert!(
        duration.as_millis() < 1000,
        "50 iterations took {}ms",
        duration.as_millis()
    );
}

#[test]
fn test_performance_large_input() {
    let arch = format!("{} with database and file system", "A".repeat(10000));
    let start = std::time::Instant::now();

    for _ in 0..10 {
        let _ = generate_threat_model_static(&arch);
    }

    let duration = start.elapsed();
    assert!(
        duration.as_millis() < 2000,
        "10 iterations with large input took {}ms",
        duration.as_millis()
    );
}

// ============================================================================
// REALISTIC SCENARIOS
// ============================================================================

#[test]
fn test_realistic_ecommerce_app() {
    let architecture = r#"=== E-commerce Platform ===
HTTP API: REST and GraphQL endpoints
database: PostgreSQL for orders, Redis for caching
file system: Product images, order receipts
Authentication: OAuth2, JWT tokens
External APIs: Payment gateway, shipping service
"#;

    let threat_model = generate_threat_model_static(architecture);

    assert!(threat_model.contains("HTTP/HTTPS API"));
    assert!(threat_model.contains("Database connection"));
    assert!(threat_model.contains("File System"));
    assert!(threat_model.contains("API key forgery"));
    assert!(threat_model.contains("SQL injection"));
    assert!(threat_model.contains("Path traversal"));
}

#[test]
fn test_realistic_microservice() {
    let architecture = r#"=== Microservice ===
HTTP API: gRPC and REST
database: PostgreSQL primary, MongoDB for logs
file system: Temporary processing files
External: Message queue, service mesh
"#;

    let threat_model = generate_threat_model_static(architecture);

    assert!(threat_model.contains("HTTP/HTTPS API"));
    assert!(threat_model.contains("Database connection"));
    assert!(threat_model.contains("File System"));
    assert!(threat_model.contains("Spoofing"));
    assert!(threat_model.contains("Tampering"));
}

#[test]
fn test_realistic_batch_processor() {
    let architecture = r#"=== Batch Processor ===
No API
file system: Input files, output reports
No database
Scheduled jobs via cron
"#;

    let threat_model = generate_threat_model_static(architecture);

    assert!(!threat_model.contains("SQL injection"));
    assert!(threat_model.contains("File System"));
    assert!(threat_model.contains("Path traversal"));
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[tokio::test]
async fn test_full_flow_with_context_persistence() {
    let tmp = tempdir().unwrap();

    // Step 1: Create initial context
    let ctx = AnalysisContext {
        project_type: baco::project_type::ProjectType::Web,
        architecture_summary: "Web app with HTTP and postgresql".to_string(),
        threat_model: None,
        invariants: Vec::new(),
        findings_so_far: Vec::new(),
    };
    ctx.save(tmp.path()).unwrap();

    // Step 2: Run threat modeling
    let result = ThreatModelingPhase::run(tmp.path(), &ctx, None).await;
    assert!(result.is_ok());

    // Step 3: Verify persistence
    let loaded = AnalysisContext::load(tmp.path()).unwrap();
    assert!(loaded.threat_model.is_some());
    assert!(loaded.threat_model.as_ref().unwrap().contains("STRIDE"));
    assert!(loaded
        .threat_model
        .as_ref()
        .unwrap()
        .contains("SQL injection"));
}

#[tokio::test]
async fn test_run_preserves_other_context_data() {
    let tmp = tempdir().unwrap();

    let ctx = AnalysisContext {
        project_type: baco::project_type::ProjectType::CLI,
        architecture_summary: "CLI tool".to_string(),
        threat_model: None,
        invariants: vec!["invariant1".to_string(), "invariant2".to_string()],
        findings_so_far: vec!["finding1".to_string()],
    };
    ctx.save(tmp.path()).unwrap();

    let _ = ThreatModelingPhase::run(tmp.path(), &ctx, None)
        .await
        .unwrap();

    let loaded = AnalysisContext::load(tmp.path()).unwrap();
    assert!(loaded.threat_model.is_some());
    assert_eq!(loaded.invariants.len(), 2);
    assert_eq!(loaded.findings_so_far.len(), 1);
}

#[test]
fn test_generate_threat_model_static_with_api_and_db() {
    let architecture = "HTTP API with PostgreSQL database".to_string();
    let result = generate_threat_model_static(&architecture);

    assert!(result.contains("TRUST BOUNDARIES"));
    assert!(result.contains("External Interface"));
    assert!(result.contains("Data Store"));
    assert!(result.contains("STRIDE"));
}

#[test]
fn test_generate_threat_model_static_with_filesystem() {
    let architecture = "File system access with file upload capability".to_string();
    let result = generate_threat_model_static(&architecture);

    assert!(result.contains("File System"));
    assert!(result.contains("Path traversal"));
}

#[test]
fn test_generate_threat_model_static_no_components() {
    let architecture = "No database, no file system, no HTTP".to_string();
    let result = generate_threat_model_static(&architecture);

    // Should still have basic structure
    assert!(result.contains("=== THREAT MODEL"));
    assert!(result.contains("TRUST BOUNDARIES"));
}

#[test]
fn test_generate_threat_model_static_variations() {
    // Test various negation patterns
    let test_cases = vec![
        "No database",
        "no database",
        "No DB",
        "no DB",
        "No file system",
        "no file system",
        "No filesystem",
        "no filesystem",
    ];

    for architecture in test_cases {
        let result = generate_threat_model_static(architecture);
        assert!(!result.is_empty());
    }
}

#[test]
fn test_load_or_generate_architecture_no_summary() {
    let tmp = tempdir().unwrap();

    // Create a simple Rust file for detection
    let src_dir = tmp.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("main.rs"), "fn main() {}").unwrap();

    let ctx = AnalysisContext {
        project_type: baco::project_type::ProjectType::CLI,
        architecture_summary: String::new(),
        threat_model: None,
        invariants: Vec::new(),
        findings_so_far: Vec::new(),
    };

    let result = load_or_generate_architecture(tmp.path(), &ctx);

    // Should generate architecture summary, not return placeholder
    assert!(result.contains("ARCHITECTURAL SUMMARY"));
    assert!(result.contains("Project type"));
    assert_ne!(result, "No architecture summary available");
}

#[test]
fn test_threat_modeling_phase_debug() {
    let phase = ThreatModelingPhase;
    let debug_output = format!("{:?}", phase);
    assert!(!debug_output.is_empty());
}

// ============================================================================
// GENERATE THREAT MODEL WITH LLM - FALLBACK PATH TESTS
// These test that when the LLM client fails, the function falls back to
// static threat model generation.
// ============================================================================

#[tokio::test]
async fn test_generate_threat_model_with_llm_fallback_to_static() {
    use baco::llm::{LlmClient, LlmConfig};

    // Create a temp directory with a minimal project
    let tmp_dir = tempdir().unwrap();
    let src_dir = tmp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("main.rs"), "fn main() {}").unwrap();

    // Create an LLM client with an invalid base URL that will fail
    let config = LlmConfig {
        base_url: "http://127.0.0.1:1".to_string(), // Unreachable port
        api_key: "invalid-key".to_string(),
        model: "test-model".to_string(),
        models: vec![],
        timeout: 1, // Very short timeout to fail fast
        max_retries: 0,
        retry_backoff_ms: 0,
        temperature: 0.5,
        max_reasoning_tokens: None,
    };
    let client = LlmClient::new(config);

    let architecture = "HTTP API with database";
    let result = generate_threat_model_with_llm(tmp_dir.path(), architecture, &client).await;

    // Should succeed with fallback to static generation
    assert!(result.is_ok());
    let threat_model = result.unwrap();

    // Verify it contains static generation markers
    assert!(threat_model.contains("TRUST BOUNDARIES"));
    assert!(threat_model.contains("STRIDE"));
    assert!(threat_model.contains("=== THREAT MODEL: STRIDE Analysis ==="));
}

#[tokio::test]
async fn test_generate_threat_model_with_llm_fallback_empty_api_key() {
    use baco::llm::{LlmClient, LlmConfig};

    // Create a temp directory with a minimal project
    let tmp_dir = tempdir().unwrap();
    let src_dir = tmp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("main.rs"), "fn main() {}").unwrap();

    // Create an LLM client with empty API key
    let config = LlmConfig {
        base_url: "https://api.openai.com/v1".to_string(),
        api_key: "".to_string(), // Empty API key
        model: "gpt-4".to_string(),
        models: vec![],
        timeout: 1,
        max_retries: 0,
        retry_backoff_ms: 0,
        temperature: 0.5,
        max_reasoning_tokens: None,
    };
    let client = LlmClient::new(config);

    let architecture = "CLI tool with file system";
    let result = generate_threat_model_with_llm(tmp_dir.path(), architecture, &client).await;

    // Should succeed with fallback to static generation
    assert!(result.is_ok());
    let threat_model = result.unwrap();

    // Verify static generation output
    assert!(threat_model.contains("TRUST BOUNDARIES"));
    assert!(threat_model.contains("STRIDE THREATS"));
}

#[tokio::test]
async fn test_generate_threat_model_with_llm_fallback_architecture_aware() {
    use baco::llm::{LlmClient, LlmConfig};

    // Create a temp directory with a minimal project
    let tmp_dir = tempdir().unwrap();
    let src_dir = tmp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("main.rs"), "fn main() {}").unwrap();

    // Create an LLM client that will fail
    let config = LlmConfig {
        base_url: "http://invalid.local:9999".to_string(),
        api_key: "test".to_string(),
        model: "test".to_string(),
        models: vec![],
        timeout: 1,
        max_retries: 0,
        retry_backoff_ms: 0,
        temperature: 0.5,
        max_reasoning_tokens: None,
    };
    let client = LlmClient::new(config);

    // Test with database architecture
    let result_with_db =
        generate_threat_model_with_llm(tmp_dir.path(), "HTTP with postgresql", &client)
            .await
            .unwrap();

    // Test without database
    let result_no_db =
        generate_threat_model_with_llm(tmp_dir.path(), "No database, just HTTP", &client)
            .await
            .unwrap();

    // With DB should contain SQL injection threats
    assert!(result_with_db.contains("SQL injection"));

    // Without DB should NOT contain SQL injection (due to "No database" negation)
    assert!(!result_no_db.contains("SQL injection"));
}

#[tokio::test]
async fn test_generate_threat_model_with_llm_fallback_all_stride_categories() {
    use baco::llm::{LlmClient, LlmConfig};

    let tmp_dir = tempdir().unwrap();
    let src_dir = tmp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("main.rs"), "fn main() {}").unwrap();

    let config = LlmConfig {
        base_url: "http://127.0.0.1:1".to_string(),
        api_key: "test".to_string(),
        model: "test".to_string(),
        models: vec![],
        timeout: 1,
        max_retries: 0,
        retry_backoff_ms: 0,
        temperature: 0.5,
        max_reasoning_tokens: None,
    };
    let client = LlmClient::new(config);

    let result = generate_threat_model_with_llm(
        tmp_dir.path(),
        "Full stack: HTTP + database + file system",
        &client,
    )
    .await
    .unwrap();

    // Verify all STRIDE categories are present
    assert!(result.contains("#### S - Spoofing"));
    assert!(result.contains("#### T - Tampering"));
    assert!(result.contains("#### R - Repudiation"));
    assert!(result.contains("#### I - Information Disclosure"));
    assert!(result.contains("#### D - Denial of Service"));
    assert!(result.contains("#### E - Elevation of Privilege"));
}

#[tokio::test]
async fn test_generate_threat_model_with_llm_fallback_various_architectures() {
    use baco::llm::{LlmClient, LlmConfig};

    let tmp_dir = tempdir().unwrap();
    let src_dir = tmp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("main.rs"), "fn main() {}").unwrap();

    let config = LlmConfig {
        base_url: "http://127.0.0.1:1".to_string(),
        api_key: "test".to_string(),
        model: "test".to_string(),
        models: vec![],
        timeout: 1,
        max_retries: 0,
        retry_backoff_ms: 0,
        temperature: 0.5,
        max_reasoning_tokens: None,
    };
    let client = LlmClient::new(config);

    let architectures = vec![
        "Simple CLI tool",
        "Web API with PostgreSQL and Redis",
        "Microservice with gRPC",
        "Batch processor with file I/O",
    ];

    for arch in architectures {
        let result = generate_threat_model_with_llm(tmp_dir.path(), arch, &client)
            .await
            .unwrap();

        // Each should produce valid static threat model
        assert!(result.contains("TRUST BOUNDARIES"));
        assert!(result.contains("STRIDE"));
    }
}
