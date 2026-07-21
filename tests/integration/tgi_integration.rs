//! Integration tests for TGI client
//!
//! These tests require a live TGI server running on localhost:8080.
//! Run with: cargo test --test tgi_integration -- --include-ignored

use baco::config::TgiConfig;
use baco::llm::TgiClient;

/// Live TGI integration test - requires TGI server running
///
/// To run this test:
/// 1. Start TGI server: `text-generation-server serve R2Vul/R2Vul-7B --port 8080`
/// 2. Run test: `cargo test --test tgi_integration -- --include-ignored`
#[tokio::test]
#[ignore] // Requires live TGI server: `cargo test --test tgi_integration -- --include-ignored`
async fn live_tgi_completes_prompt() {
    // Skip if TGI server is not available
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "R2Vul/R2Vul-7B".to_string(), // Replace with actual model
        max_new_tokens: 1024,
        temperature: 0.1,
        timeout_secs: 120,
        do_sample: true,
    };

    let client = match TgiClient::new(&config) {
        Ok(c) => c,
        Err(_) => {
            // TGI server not available, skip test
            println!("Skipping test - TGI server not available");
            return;
        }
    };

    // Verify server is healthy
    assert!(client.is_available(), "TGI server health check failed");

    // Test completion
    let prompt = "Analyze this C code for buffer overflow vulnerabilities: void copy(char *dst, char *src) { strcpy(dst, src); }";
    let result = client.complete(prompt).await;

    assert!(result.is_ok(), "TGI completion failed: {:?}", result.err());
    let response = result.unwrap();
    assert!(!response.is_empty(), "TGI returned empty response");

    println!("TGI response: {}", response);
}

/// Live TGI health check test
#[test]
#[ignore] // Requires live TGI server: `cargo test --test tgi_integration -- --include-ignored`
fn live_tgi_health_check() {
    let config = TgiConfig {
        enabled: true,
        endpoint: "http://localhost:8080".to_string(),
        model: "R2Vul/R2Vul-7B".to_string(),
        max_new_tokens: 1024,
        temperature: 0.1,
        timeout_secs: 120,
        do_sample: true,
    };

    let client = match TgiClient::new(&config) {
        Ok(c) => c,
        Err(_) => {
            println!("Skipping test - TGI server not available");
            return;
        }
    };

    assert!(client.is_available(), "TGI server health check failed");
}
