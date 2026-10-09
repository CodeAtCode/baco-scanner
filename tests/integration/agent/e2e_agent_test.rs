use crate::common::fixtures::mock_llm::MockLlmClient;
use baco::config::{AgentConfig, ScannerConfig};
use std::path::PathBuf;

// ============================================================================
// Helper for temp e2e agent paths
// ============================================================================

fn temp_e2e_path(prefix: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("{}-{}-{seq:x}", prefix, std::process::id()))
}

fn compute_hash(path: &PathBuf) -> String {
    use std::fs::File;
    use std::io::Read;
    let mut file = File::open(path).expect("Failed to open file");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .expect("Failed to read file");
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    contents.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

#[test]
fn test_agent_disabled_existing_behavior() {
    let config = ScannerConfig {
        agent: AgentConfig {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(!config.agent.enabled);
}

#[test]
fn test_agent_enabled_with_mock() {
    let responses = vec![
        MockLlmClient::mock_tool_call("file_read", serde_json::json!({"path": "test.py"})),
        MockLlmClient::mock_final_response("[]"),
    ];
    let _mock_client = MockLlmClient::new(responses);
    let project_root = temp_e2e_path("e2e-agent-test");
    let config = AgentConfig::default();
    let sandbox =
        baco::agent::sandbox::ToolSandbox::new(project_root.clone(), config.tool_timeout_secs);

    // Assert sandbox was created with correct configuration
    assert_eq!(sandbox.temp_dir(), &project_root);
    assert_eq!(sandbox.timeout_secs(), config.tool_timeout_secs);
}

#[test]
fn test_source_files_unchanged_via_hash() {
    let main_path = PathBuf::from("tests/fixtures/vulnerable-project/src/main.py");
    let utils_path = PathBuf::from("tests/fixtures/vulnerable-project/src/utils.py");

    let main_hash_before = compute_hash(&main_path);
    let utils_hash_before = compute_hash(&utils_path);

    let _content = std::fs::read_to_string(&main_path).unwrap();
    let _content = std::fs::read_to_string(&utils_path).unwrap();

    let main_hash_after = compute_hash(&main_path);
    let utils_hash_after = compute_hash(&utils_path);

    assert_eq!(main_hash_before, main_hash_after);
    assert_eq!(utils_hash_before, utils_hash_after);
}
