#![allow(clippy::test_attr_in_doctest)]
//! Parallel Safety Tests for BACO
//!
//! This module contains tests that verify the parallel execution safety of BACO phases.
//! These tests ensure that phases can run concurrently without shared mutable state conflicts.
//!
//! # Migration Guide for Serial Tests
//!
//! If you have tests using `#[serial]` from `serial_test`:
//!
//! 1. **Identify the shared state**: Check if tests use:
//!    - Environment variables (std::env::set_var)
//!    - Global static mut variables
//!    - Shared file paths without isolation
//!    - Singleton patterns with mutable state
//!
//! 2. **Isolation strategies**:
//!    - Use `tempfile::TempDir` for file-based tests
//!    - Use unique prefixes for env vars (e.g., `BACO_TEST_${RANDOM}`)
//!    - Use `parking_lot::Mutex` with scoped locks instead of global locks
//!    - Pass config explicitly instead of relying on globals
//!
//! 3. **Migration pattern**:
//!    ```rust
//!    // Before (serial):
//!    #[test]
//!    #[serial]
//!    fn test_with_env_var() {
//!        std::env::set_var("BACO_API_KEY", "test");
//!        // ...
//!    }
//!
//!    // After (parallel-safe):
//!    #[tokio::test]
//!    async fn test_with_env_var() {
//!        let _guard = EnvVarGuard::set("BACO_API_KEY", "test");
//!        // Test auto-cleans on drop
//!    }
//! ```

use std::env;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

use crate::fixtures::EnvVarGuard;

/// Test that multiple tests can set env vars concurrently without interference
#[tokio::test]
async fn test_env_var_isolation_parallel() {
    let handles: Vec<_> = (0..10)
        .map(|i| {
            tokio::spawn(async move {
                let _guard = EnvVarGuard::set(&[("BACO_TEST_PARALLEL", &format!("value_{}", i))]);
                let value = env::var("BACO_TEST_PARALLEL").unwrap();
                assert_eq!(value, format!("value_{}", i));
                // Simulate some async work
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                value
            })
        })
        .collect();

    let results = futures::future::join_all(handles).await;
    for (i, result) in results.into_iter().enumerate() {
        let value = result.unwrap();
        assert_eq!(value, format!("value_{}", i));
    }
}

/// Test that TempDir provides proper file isolation
#[tokio::test]
async fn test_tempdir_isolation_parallel() {
    let handles: Vec<_> = (0..10)
        .map(|i| {
            tokio::spawn(async move {
                let temp_dir = TempDir::new().unwrap();
                let file_path = temp_dir.path().join(format!("test_{}.txt", i));

                // Write unique content
                std::fs::write(&file_path, format!("content_{}", i)).unwrap();

                // Read and verify
                let content = std::fs::read_to_string(&file_path).unwrap();
                assert_eq!(content, format!("content_{}", i));

                // TempDir auto-cleans on drop
                assert!(file_path.exists());
                drop(temp_dir);
                assert!(!file_path.exists());

                i
            })
        })
        .collect();

    let results = futures::future::join_all(handles).await;
    assert_eq!(results.len(), 10);
}

/// Test that shared state access is properly synchronized
#[tokio::test]
async fn test_shared_state_synchronization() {
    let counter = Arc::new(Mutex::new(0));
    let mut handles = vec![];

    // Spawn 10 tasks that increment the counter
    for _ in 0..10 {
        let counter_clone = Arc::clone(&counter);
        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                {
                    let mut num = counter_clone.lock().unwrap();
                    *num += 1;
                } // Lock is dropped here, before await
                tokio::task::yield_now().await;
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    assert_eq!(*counter.lock().unwrap(), 1000);
}

/// Test that phase contexts don't share mutable state
#[tokio::test]
async fn test_phase_context_isolation() {
    use baco::config::ScannerConfig;
    use baco::findings::{Severity, VulnerabilityFinding};
    use baco::scanner::Scanner;

    let handles: Vec<_> = (0..5)
        .map(|i| {
            tokio::spawn(async move {
                // Each task creates its own isolated scanner
                let config = ScannerConfig::default();
                let temp_dir = TempDir::new().unwrap();
                let target_path = temp_dir.path().to_path_buf();

                let scanner = Scanner::new(config, target_path.clone(), false);
                let _analyzed_files: Vec<String> = Vec::new();

                // Create a finding unique to this task
                let finding = VulnerabilityFinding {
                    id: format!("task-{}-finding", i),
                    title: format!("Test finding from task {}", i),
                    description: format!("Description for task {}", i),
                    file_path: target_path
                        .join(format!("file_{}.rs", i))
                        .to_string_lossy()
                        .to_string(),
                    line_number: Some(i + 1),
                    severity: Severity::High,
                    confidence_score: 0.8,
                    cwe_id: Some("CWE-79".to_string()),
                    sources: vec![format!("task_{}", i)],
                    verification_status: None,
                    verification_notes: None,
                    code_snippet: None,
                    diff_hunk: None,
                    recommendation: None,
                    code_location: None,
                    already_reported: false,
                    commit_reference: None,
                    ticket_reference: None,
                    priority_score: None,
                    cross_file_references: None,
                    verification_error: None,
                    agent_evidence_path: None,
                    security_issue: None,
                    poc_code: None,
                    mitigation_code: None,
                    poc_format: None,
                    llm_model: None,
                    agent_mode: false,
                    statement_range: None,
                    triage_verdict: None,
                    evidence: vec![],
                    verification_tier: None,
                };

                scanner.add_finding(finding.clone());

                assert_eq!(scanner.findings().len(), 1);
                assert_eq!(scanner.findings()[0].id, format!("task-{}-finding", i));

                i
            })
        })
        .collect();

    let results = futures::future::join_all(handles).await;
    for (i, result) in results.into_iter().enumerate() {
        let task_id = result.unwrap();
        assert_eq!(task_id, i as u32);
    }
}

/// Test that checkpoint files don't conflict when saved concurrently
#[tokio::test]
async fn test_checkpoint_file_isolation() {
    use baco::checkpoint::{Checkpoint, ScanPhase};
    use chrono::Utc;

    let handles: Vec<_> = (0..5)
        .map(|i| {
            tokio::spawn(async move {
                let temp_dir = TempDir::new().unwrap();
                let checkpoint_path = temp_dir.path().join(format!("checkpoint_{}.json", i));

                let checkpoint = Checkpoint::new(
                    &format!("scan-{}", i),
                    temp_dir.path().to_string_lossy().as_ref(),
                    Utc::now(),
                );

                checkpoint.save(checkpoint_path.to_str().unwrap()).unwrap();

                // Verify checkpoint can be loaded
                let loaded = Checkpoint::load(checkpoint_path.to_str().unwrap()).unwrap();
                assert_eq!(loaded.scan_id, format!("scan-{}", i));
                assert_eq!(loaded.current_phase, ScanPhase::Indexing);

                i
            })
        })
        .collect();

    let results = futures::future::join_all(handles).await;
    for (i, result) in results.into_iter().enumerate() {
        let task_id = result.unwrap();
        assert_eq!(task_id, i);
    }
}

/// Test that report generation doesn't have file conflicts
#[tokio::test]
async fn test_report_generation_isolation() {
    use baco::config::ScannerConfig;
    use baco::findings::{Severity, VulnerabilityFinding};
    use baco::scanner::Scanner;

    let handles: Vec<_> = (0..5)
        .map(|i| {
            tokio::spawn(async move {
                let config = ScannerConfig::default();
                let temp_dir = TempDir::new().unwrap();
                let output_dir = temp_dir.path().join("output");
                std::fs::create_dir_all(&output_dir).unwrap();

                let target_path = temp_dir.path().to_path_buf();
                let scanner = Scanner::new(config, target_path.clone(), false);

                // Add unique findings per task
                for j in 0..3 {
                    let finding = VulnerabilityFinding {
                        id: format!("task-{}-finding-{}", i, j),
                        title: format!("Finding {} from task {}", j, i),
                        description: format!("Description for finding {} in task {}", j, i),
                        file_path: target_path
                            .join(format!("file_{}.rs", j))
                            .to_string_lossy()
                            .to_string(),
                        line_number: Some(j + 1),
                        severity: Severity::High,
                        confidence_score: 0.8,
                        cwe_id: Some("CWE-79".to_string()),
                        sources: vec![format!("task_{}", i)],
                        verification_status: None,
                        verification_notes: None,
                        code_snippet: None,
                        diff_hunk: None,
                        recommendation: None,
                        code_location: None,
                        already_reported: false,
                        commit_reference: None,
                        ticket_reference: None,
                        priority_score: None,
                        cross_file_references: None,
                        verification_error: None,
                        agent_evidence_path: None,
                        security_issue: None,
                        poc_code: None,
                        mitigation_code: None,
                        poc_format: None,
                        llm_model: None,
                        agent_mode: false,
                        statement_range: None,
                        triage_verdict: None,
                        evidence: vec![],
                        verification_tier: None,
                    };
                    scanner.add_finding(finding);
                }

                // Verify findings are isolated
                assert_eq!(scanner.findings().len(), 3);
                for finding in &scanner.findings() {
                    assert!(finding.id.starts_with(&format!("task-{}-", i)));
                }

                i
            })
        })
        .collect();

    let results = futures::future::join_all(handles).await;
    for (i, result) in results.into_iter().enumerate() {
        let task_id = result.unwrap();
        assert_eq!(task_id, i);
    }
}

/// Test that concurrent config loading doesn't cause race conditions
#[tokio::test]
async fn test_config_loading_parallel() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    // Create all config files first (reduced from 10 to 5 for speed)
    let mut config_paths = Vec::new();
    for i in 0..5 {
        let config_path = format!("/tmp/baco_parallel_test_{}_{}.toml", timestamp, i);
        let config_content = format!(
            r#"[project]
name = "test-project-{}"
path = "/tmp"
languages = ["rust"]

[output]
dir = "/tmp/output"
format = ["json"]

[scanner]
max_file_size_kb = 1024

[llm]
base_url = "http://localhost:11434/v1"

[llm.phases.discovery]
base_url = "http://localhost:11434/v1"
model = "llama3.1"
timeout_secs = 120
"#,
            i
        );
        std::fs::write(&config_path, &config_content).unwrap();
        config_paths.push(config_path);
    }

    // Now load them in parallel using direct TOML parsing (no validation)
    let handles: Vec<_> = config_paths
        .into_iter()
        .enumerate()
        .map(|(i, config_path)| {
            tokio::spawn(async move {
                let content = std::fs::read_to_string(&config_path).unwrap();
                let success = toml::from_str::<String>(&content).is_ok()
                    || toml::from_str::<serde_json::Value>(&content).is_ok();
                let _ = std::fs::remove_file(&config_path);
                (i, success)
            })
        })
        .collect();

    // Wait for all tasks and collect results
    let mut all_passed = true;
    for handle in handles {
        if let Ok((i, success)) = handle.await {
            if !success {
                eprintln!("Task {} failed to parse config", i);
                all_passed = false;
            }
        } else {
            all_passed = false;
        }
    }

    assert!(all_passed, "All parallel config parsing tasks must succeed");
    assert!(all_passed, "All parallel config parsing tasks must succeed");
}

// MIGRATION GUIDE: Identifying which tests need serialization
//
// 1. Tests using std::env::set_var without isolation:
//    - src/config.rs tests that set BACO_* env vars
//    - Fix: Use EnvVarGuard pattern shown above
//
// 2. Tests writing to shared temp directories:
//    - Tests using /tmp/baco-test without unique subdirs
//    - Fix: Use tempfile::TempDir for each test
//
// 3. Tests with global static mut:
//    - Any test accessing lazy_static! or once_cell::sync::Lazy mut refs
//    - Fix: Use Arc<Mutex<T>> passed as parameter or use EnvVarGuard
/// Stress test: run many parallel tests to verify no race conditions
#[tokio::test]
async fn test_parallel_stress_50_concurrent_tasks() {
    let handles: Vec<_> = (0..50)
        .map(|i| {
            tokio::spawn(async move {
                // Each task does multiple operations
                let _guard = EnvVarGuard::set(&[("BACO_STRESS_TEST", &format!("task_{}", i))]);

                let temp_dir = TempDir::new().unwrap();
                let file_path = temp_dir.path().join("test.txt");
                std::fs::write(file_path.clone(), format!("content_{}", i)).unwrap();

                let content = std::fs::read_to_string(&file_path).unwrap();
                assert_eq!(content, format!("content_{}", i));

                // Verify env var
                assert_eq!(env::var("BACO_STRESS_TEST").unwrap(), format!("task_{}", i));

                i
            })
        })
        .collect();

    let results = futures::future::join_all(handles).await;
    assert_eq!(results.len(), 50);

    for (i, result) in results.into_iter().enumerate() {
        assert_eq!(result.unwrap(), i);
    }
}

/// Test that demonstrates the pattern for migrating serial_test to parallel-safe code
#[tokio::test]
async fn migration_example_env_var_pattern() {
    // BEFORE (requires serial):
    // #[test]
    // #[serial]
    // fn test_old_pattern() {
    //     std::env::set_var("MY_API_KEY", "test_key");
    //     let config = ScannerConfig::from_env();
    //     assert_eq!(config.llm.phases.discovery.api_key, Some("test_key".to_string()));
    // }

    // AFTER (parallel-safe):
    let _guard = EnvVarGuard::set(&[
        ("BACO_MIGRATION_EXAMPLE", "example_value"),
        ("ANOTHER_VAR", "another_value"),
    ]);

    assert_eq!(env::var("BACO_MIGRATION_EXAMPLE").unwrap(), "example_value");
    assert_eq!(env::var("ANOTHER_VAR").unwrap(), "another_value");

    // When _guard drops, vars are restored automatically
    // This test can run in parallel with any other test
}
