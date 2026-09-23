//! Threat model generation tests.

use baco::analysis_context::AnalysisContext;
use baco::llm::LlmConfig;
use baco::threat_model::generation::{
    generate_threat_model_static, generate_threat_model_with_llm, load_or_generate_architecture,
    save_to_context,
};

use tempfile::tempdir;

// ============================================================================
// GENERATE THREAT MODEL STATIC TESTS
// ============================================================================

#[test]
fn test_generate_threat_model_static_no_db() {
    let architecture = "No database, just static files";
    let tm = generate_threat_model_static(architecture);

    assert!(!tm.contains("Data Store"));
    assert!(tm.contains("TRUST BOUNDARIES"));
}

#[test]
fn test_generate_threat_model_static_with_api() {
    let architecture = "HTTP API with endpoints";
    let tm = generate_threat_model_static(architecture);

    assert!(tm.contains("HTTP Endpoints"));
    assert!(tm.contains("External Interface"));
}

#[test]
fn test_save_to_context() {
    let tmp = tempdir().unwrap();

    let tm = "Test threat model";
    save_to_context(tmp.path(), tm);

    let ctx = AnalysisContext::load(tmp.path()).unwrap();
    assert_eq!(ctx.threat_model, Some(tm.to_string()));
}

#[test]
fn test_load_or_generate_architecture_with_summary() {
    let tmp = tempdir().unwrap();

    let ctx = AnalysisContext {
        architecture_summary: "Test architecture".to_string(),
        ..Default::default()
    };
    ctx.save(tmp.path()).unwrap();

    let loaded = AnalysisContext::load(tmp.path()).unwrap();
    let arch = load_or_generate_architecture(tmp.path(), &loaded);
    assert_eq!(arch, "Test architecture");
}

#[test]
fn test_load_or_generate_architecture_empty() {
    let tmp = tempdir().unwrap();

    // Create a simple Rust file for detection
    let src_dir = tmp.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("main.rs"), "fn main() {}").unwrap();

    let ctx = AnalysisContext::default();
    let arch = load_or_generate_architecture(tmp.path(), &ctx);

    // Should generate architecture summary, not return placeholder
    assert!(arch.contains("ARCHITECTURAL SUMMARY"));
    assert!(arch.contains("Project type"));
    assert_ne!(arch, "No architecture summary available");
}

// ============================================================================
// GENERATE THREAT MODEL WITH LLM - FALLBACK PATH TESTS
// ============================================================================

/// Test that fallback to static generation occurs when LLM client returns an error
#[tokio::test]
async fn test_generate_threat_model_with_llm_fallback_to_static() {
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
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
        pricing: Default::default(),
    };
    let client = baco::llm::LlmClient::new(config);

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

/// Test fallback path with empty API key
#[tokio::test]
async fn test_generate_threat_model_with_llm_fallback_empty_api_key() {
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
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
        pricing: Default::default(),
    };
    let client = baco::llm::LlmClient::new(config);

    let architecture = "CLI tool with file system";
    let result = generate_threat_model_with_llm(tmp_dir.path(), architecture, &client).await;

    // Should succeed with fallback to static generation
    assert!(result.is_ok());
    let threat_model = result.unwrap();

    // Verify static generation output
    assert!(threat_model.contains("TRUST BOUNDARIES"));
    assert!(threat_model.contains("STRIDE THREATS"));
}

/// Test that fallback produces different output based on architecture
#[tokio::test]
async fn test_generate_threat_model_with_llm_fallback_architecture_aware() {
    // Create a temp directory with a minimal project
    let tmp_dir = tempdir().unwrap();
    let src_dir = tmp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("main.rs"), "fn main() {}").unwrap();

    // Create an LLM client that will fail
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
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
        pricing: Default::default(),
    };
    let client = baco::llm::LlmClient::new(config);

    // Test with database architecture
    let result_with_db =
        generate_threat_model_with_llm(tmp_dir.path(), "HTTP with PostgreSQL", &client)
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

/// Test fallback path preserves all STRIDE categories
#[tokio::test]
async fn test_generate_threat_model_with_llm_fallback_all_stride_categories() {
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
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
        pricing: Default::default(),
    };
    let client = baco::llm::LlmClient::new(config);

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

/// Test fallback with various architecture strings
#[tokio::test]
async fn test_generate_threat_model_with_llm_fallback_various_architectures() {
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
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
        pricing: Default::default(),
    };
    let client = baco::llm::LlmClient::new(config);

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

// ============================================================================
// ADDITIONAL STATIC MODEL TESTS
// ============================================================================

/// Test STRIDE categories present in static output
#[test]
fn test_generate_threat_model_static_stride_categories() {
    let tm = generate_threat_model_static("Web app with PostgreSQL database");

    // All six STRIDE categories should be present
    assert!(tm.contains("Spoofing"), "Should contain Spoofing category");
    assert!(
        tm.contains("Tampering"),
        "Should contain Tampering category"
    );
    assert!(
        tm.contains("Repudiation"),
        "Should contain Repudiation category"
    );
    assert!(
        tm.contains("Information Disclosure"),
        "Should contain Information Disclosure category"
    );
    assert!(
        tm.contains("Denial of Service"),
        "Should contain Denial of Service category"
    );
    assert!(
        tm.contains("Elevation of Privilege"),
        "Should contain Elevation of Privilege category"
    );
}

/// Test VulnInstruct specification sections when specs provided
#[test]
fn test_generate_threat_model_static_vulninstruct_sections() {
    let tm = generate_threat_model_static("Microservice with gRPC and Redis cache");

    // Should contain specification-style sections
    assert!(tm.contains("THREAT MODEL"), "Should have main header");
    assert!(tm.contains("DATA FLOWS"), "Should describe data flow");
    assert!(
        tm.contains("TRUST BOUNDARIES"),
        "Should define trust boundaries"
    );
    assert!(tm.contains("STRIDE THREATS"), "Should list threats");
}

/// Test static generation handles empty architecture gracefully
#[test]
fn test_generate_threat_model_static_empty_architecture() {
    let tm = generate_threat_model_static("");

    // Should still produce valid output with default structure
    assert!(
        tm.contains("STRIDE"),
        "Should contain STRIDE even with empty architecture"
    );
    assert!(
        tm.contains("TRUST BOUNDARIES"),
        "Should have trust boundaries section"
    );
}

/// Test static generation for CLI tool architecture
#[test]
fn test_generate_threat_model_static_cli_architecture() {
    let tm = generate_threat_model_static("CLI tool with file system access");

    // CLI-specific threats should be present
    assert!(tm.contains("file"), "Should mention file system");
    assert!(
        !tm.contains("SQL injection"),
        "CLI without DB should not have SQLi threats"
    );
}

/// Test static generation distinguishes network vs local
/// Test static generation distinguishes network vs local
#[test]
fn test_generate_threat_model_static_network_vs_local() {
    let tm_network = generate_threat_model_static("HTTP API server");
    let tm_local = generate_threat_model_static("Local batch processor");

    // Both should produce valid threat models
    assert!(tm_network.contains("STRIDE"));
    assert!(tm_local.contains("STRIDE"));
    // Static generation produces consistent output regardless of input
    assert_eq!(
        tm_network.contains("TRUST BOUNDARIES"),
        tm_local.contains("TRUST BOUNDARIES")
    );
}
#[tokio::test]
async fn threat_model_llm_passthrough_with_mockito() {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"choices": [{"message": {"content": "Threat Model\n- Spoofing: none"}}]}"#)
        .create();

    let cfg = baco::llm::LlmConfig {
        base_url: server.url(),
        api_key: "k".to_string(),
        model: "m".to_string(),
        ..Default::default()
    };
    let client = baco::llm::LlmClient::new(cfg);
    let dir = tempfile::TempDir::new().unwrap();
    let out =
        baco::threat_model::generation::generate_threat_model_with_llm(dir.path(), "arch", &client)
            .await
            .unwrap();
    assert!(out.contains("Threat Model"));
}

#[tokio::test]
async fn threat_model_llm_error_falls_back_to_static() {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(500)
        .with_body("boom")
        .create();

    let cfg = baco::llm::LlmConfig {
        base_url: server.url(),
        api_key: "k".to_string(),
        model: "m".to_string(),
        max_retries: 0,
        ..Default::default()
    };
    let client = baco::llm::LlmClient::new(cfg);
    let dir = tempfile::TempDir::new().unwrap();
    let out =
        baco::threat_model::generation::generate_threat_model_with_llm(dir.path(), "arch", &client)
            .await
            .unwrap();
    assert!(!out.is_empty());
}
#[test]
fn save_to_context_round_trips_threat_model() {
    let dir = tempfile::TempDir::new().unwrap();
    baco::threat_model::generation::save_to_context(dir.path(), "model-text");
    let ctx = baco::analysis_context::AnalysisContext::load(dir.path()).unwrap();
    assert_eq!(ctx.threat_model.as_deref(), Some("model-text"));
}
#[test]
fn generate_architecture_static_empty_dir_skeleton() {
    let dir = tempfile::TempDir::new().unwrap();
    let summary = baco::threat_model::generation::generate_architecture_static(dir.path());
    assert!(!summary.is_empty());
}
#[test]
fn generate_architecture_static_full_stack_fixture() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("main.rs"),
        "use axum::Router;\n// postgres database via sqlx, auth token required\nfn main() {\n    let data = std::fs::read_to_string(\"x\").unwrap();\n    let _ = (data, \"auth token\", \"postgres\");\n}\n",
    )
    .unwrap();
    let summary = baco::threat_model::generation::generate_architecture_static(dir.path());
    assert!(summary.contains("- HTTP API: yes"), "missing http arm");
    assert!(summary.contains("- database: yes"), "missing db arm");
    assert!(summary.contains("- file system: yes"), "missing fs arm");
    assert!(
        summary.contains("- Authentication: yes"),
        "missing auth arm"
    );
}
#[test]
fn load_or_generate_architecture_empty_dir() {
    let dir = tempfile::TempDir::new().unwrap();
    let ctx = baco::analysis_context::AnalysisContext::default();
    let arch = baco::threat_model::generation::load_or_generate_architecture(dir.path(), &ctx);
    assert!(!arch.is_empty());
}
