//! Unit tests for the typed error taxonomy (ScanError)
//!
//! Tests cover:
//! - Variant construction and Display formatting
//! - is_retryable() classification
//! - with_phase() context attachment
//! - From<reqwest::Error> and From<serde_json::Error> conversions
//! - Phase error round-trip

use baco::error::ScanError;
use baco::error::ScanResult;

#[test]
fn test_auth_error_is_non_retryable() {
    let err = ScanError::Auth {
        message: "API key invalid".to_string(),
        source: None,
    };
    assert!(!err.is_retryable());
    let display = format!("{}", err);
    assert!(display.contains("Authentication failed"));
    assert!(display.contains("API key invalid"));
}

#[test]
fn test_network_error_is_retryable() {
    let err = ScanError::Network {
        message: "Connection refused".to_string(),
        source: None,
    };
    assert!(err.is_retryable());
    let display = format!("{}", err);
    assert!(display.contains("Network error"));
}

#[test]
fn test_timeout_error_is_retryable() {
    let err = ScanError::Timeout {
        message: "Request timed out".to_string(),
        source: None,
    };
    assert!(err.is_retryable());
}

#[test]
fn test_rate_limit_error_is_retryable() {
    let err = ScanError::RateLimit {
        message: "Rate limit exceeded".to_string(),
        source: None,
    };
    assert!(err.is_retryable());
}

#[test]
fn test_parse_error_is_non_retryable() {
    let err = ScanError::Parse {
        message: "Invalid JSON".to_string(),
        source: None,
    };
    assert!(!err.is_retryable());
}

#[test]
fn test_config_error_is_non_retryable() {
    let err = ScanError::Config {
        message: "Missing required field".to_string(),
        source: None,
    };
    assert!(!err.is_retryable());
}

#[test]
fn test_with_phase_adds_context() {
    let err = ScanError::Network {
        message: "Connection failed".to_string(),
        source: None,
    };
    let err_with_phase = err.with_phase("llm_verification");
    assert!(matches!(err_with_phase, ScanError::Phase { .. }));
    let display = format!("{}", err_with_phase);
    assert!(display.contains("Phase 'llm_verification' failed"));
    assert!(display.contains("Connection failed"));
}

#[test]
fn test_phase_error_round_trips_phase_name() {
    let err = ScanError::Phase {
        message: "Something went wrong".to_string(),
        phase: "discovery".to_string(),
        source: None,
    };
    assert_eq!(err.phase(), Some("discovery"));
    let display = format!("{}", err);
    assert!(display.contains("Phase 'discovery' failed"));
}

#[test]
fn test_from_reqwest_error_maps_to_retryable_network() {
    // Test 429 RateLimit - retryable
    // Note: HTTP error status codes return Ok(Response), not Err.
    // We use error_for_status() to convert them to reqwest::Error
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/rate-limit")
        .with_status(429)
        .with_body("Too Many Requests")
        .create();

    let client = reqwest::Client::new();
    let url = server.url() + "/rate-limit";
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        let resp = client.get(&url).send().await?;
        resp.error_for_status()
    });

    match result {
        Ok(_) => panic!("Expected error for 429 response"),
        Err(reqwest_err) => {
            let scan_err = ScanError::from_reqwest(reqwest_err);
            assert!(
                matches!(scan_err, ScanError::RateLimit { .. }),
                "Expected RateLimit variant for 429, got {:?}",
                scan_err
            );
            assert!(scan_err.is_retryable(), "429 should be retryable");
        }
    }
    mock.assert();
}

#[test]
fn test_from_reqwest_401_maps_to_auth_non_retryable() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/unauthorized")
        .with_status(401)
        .with_body("Unauthorized")
        .create();

    let client = reqwest::Client::new();
    let url = server.url() + "/unauthorized";
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        let resp = client.get(&url).send().await?;
        resp.error_for_status()
    });

    match result {
        Ok(_) => panic!("Expected error for 401 response"),
        Err(reqwest_err) => {
            let scan_err = ScanError::from_reqwest(reqwest_err);
            assert!(
                matches!(scan_err, ScanError::Auth { .. }),
                "Expected Auth variant for 401, got {:?}",
                scan_err
            );
            assert!(!scan_err.is_retryable(), "401 should be non-retryable");
        }
    }
    mock.assert();
}

#[test]
fn test_from_reqwest_403_maps_to_auth_non_retryable() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/forbidden")
        .with_status(403)
        .with_body("Forbidden")
        .create();

    let client = reqwest::Client::new();
    let url = server.url() + "/forbidden";
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        let resp = client.get(&url).send().await?;
        resp.error_for_status()
    });

    match result {
        Ok(_) => panic!("Expected error for 403 response"),
        Err(reqwest_err) => {
            let scan_err = ScanError::from_reqwest(reqwest_err);
            assert!(
                matches!(scan_err, ScanError::Auth { .. }),
                "Expected Auth variant for 403, got {:?}",
                scan_err
            );
            assert!(!scan_err.is_retryable(), "403 should be non-retryable");
        }
    }
    mock.assert();
}

#[test]
fn test_from_reqwest_500_maps_to_server_retryable() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/server-error")
        .with_status(500)
        .with_body("Internal Server Error")
        .create();

    let client = reqwest::Client::new();
    let url = server.url() + "/server-error";
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        let resp = client.get(&url).send().await?;
        resp.error_for_status()
    });

    match result {
        Ok(_) => panic!("Expected error for 500 response"),
        Err(reqwest_err) => {
            let scan_err = ScanError::from_reqwest(reqwest_err);
            assert!(
                matches!(scan_err, ScanError::Server { .. }),
                "Expected Server variant for 500, got {:?}",
                scan_err
            );
            assert!(scan_err.is_retryable(), "500 should be retryable");
        }
    }
    mock.assert();
}

#[test]
fn test_from_reqwest_503_maps_to_server_retryable() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/service-unavailable")
        .with_status(503)
        .with_body("Service Unavailable")
        .create();

    let client = reqwest::Client::new();
    let url = server.url() + "/service-unavailable";
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async {
        let resp = client.get(&url).send().await?;
        resp.error_for_status()
    });

    match result {
        Ok(_) => panic!("Expected error for 503 response"),
        Err(reqwest_err) => {
            let scan_err = ScanError::from_reqwest(reqwest_err);
            assert!(
                matches!(scan_err, ScanError::Server { .. }),
                "Expected Server variant for 503, got {:?}",
                scan_err
            );
            assert!(scan_err.is_retryable(), "503 should be retryable");
        }
    }
    mock.assert();
}

#[test]
fn test_from_json_error_maps_to_parse_non_retryable() {
    let json_str = "invalid json";
    let json_err: serde_json::Error =
        serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
    let scan_err = ScanError::from_json_error(json_err);
    assert!(!scan_err.is_retryable());
    assert!(matches!(scan_err, ScanError::Parse { .. }));
}

#[test]
fn test_server_error_is_retryable() {
    let err = ScanError::Server {
        message: "Internal server error".to_string(),
        source: None,
    };
    assert!(err.is_retryable());
}

#[test]
fn test_unknown_error_is_non_retryable() {
    let err = ScanError::Unknown("something unexpected".to_string());
    assert!(!err.is_retryable());
}

// ============================================================================
// Additional error.rs inline tests (migrated)
// ============================================================================

#[test]
fn test_scan_error_missing_env_var() {
    let err = ScanError::MissingEnvVar("API_KEY".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Missing required environment variable"));
    assert!(display.contains("API_KEY"));
}

#[test]
fn test_scan_error_config_error() {
    let err = ScanError::Config {
        message: "invalid config".to_string(),
        source: None,
    };
    let display = format!("{}", err);
    assert!(display.contains("Configuration error"));
    assert!(display.contains("invalid config"));
}

#[test]
fn test_scan_error_from_string() {
    let err: ScanError = "something went wrong".into();
    match err {
        ScanError::Unknown(msg) => assert_eq!(msg, "something went wrong"),
        _ => panic!("Expected Unknown variant"),
    }
}

#[test]
fn test_scan_error_from_str() {
    let err: ScanError = "error message".into();
    match err {
        ScanError::Unknown(msg) => assert_eq!(msg, "error message"),
        _ => panic!("Expected Unknown variant"),
    }
}

#[test]
fn test_scan_error_debug() {
    let err = ScanError::Validation("invalid value".to_string());
    let debug = format!("{:?}", err);
    assert!(debug.contains("Validation"));
}

#[test]
fn test_scan_error_is_error() {
    let err = ScanError::Unknown("test".to_string());
    let _: &dyn std::error::Error = &err;

    assert!(
        format!("{:?}", err).contains("Unknown"),
        "Debug should name the variant so logs stay diagnosable"
    );
    assert!(
        std::error::Error::source(&err).is_none(),
        "a leaf error carries no source"
    );
}

#[test]
fn test_scan_result_type_alias() {
    let result: ScanResult<String> = Ok("success".to_string());
    match result {
        Ok(s) => assert_eq!(s, "success"),
        Err(_) => panic!("Expected Ok"),
    }

    let result: ScanResult<String> = Err(ScanError::Unknown("error".to_string()));
    match result {
        Ok(_) => panic!("Expected Err"),
        Err(e) => assert_eq!(e.to_string(), "Unknown error: error"),
    }
}
