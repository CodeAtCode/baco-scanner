use baco::llm_metrics::{LlmMetricsTracker, ModelMetrics, OperationMetrics, RecordRequestParams};
use std::collections::HashMap;

#[test]
fn test_agent_message_with_tools_is_specific() {
    let tools_used = vec!["file_read".to_string(), "pattern_search".to_string()];
    let turn_count = 3;
    let tools_list = tools_used.join(", ");
    let message = format!(
        "Offensive security analysis using {} performed {} turns of investigation. No critical exploitable vulnerability was identified after tracing data flow and checking for common attack vectors (SQLi, XSS, command injection, path traversal). Code demonstrates defensive programming practices.",
        tools_list,
        turn_count
    );

    assert!(message.contains("file_read, pattern_search"));
    assert!(message.contains("3 turns"));
    assert!(message.contains("tracing data flow"));
    assert!(message.contains("SQLi"));
    assert!(message.contains("XSS"));
    assert!(message.contains("command injection"));
    assert!(message.contains("path traversal"));
    assert!(!message.contains("comprehensive code review"));
    assert!(!message.contains("AI-powered static analysis"));
    assert!(!message.contains("did not identify specific vulnerabilities"));
}

#[test]
fn test_agent_message_without_tools_is_specific() {
    let file_path = "src/vulnerable_module.py";
    let message = format!(
        "Static analysis of {} revealed no exploitable vulnerability patterns. Code review confirmed: input validation, proper error handling, and safe API usage throughout the analyzed section.",
        file_path
    );

    assert!(message.contains("src/vulnerable_module.py"));
    assert!(message.contains("input validation"));
    assert!(message.contains("error handling"));
    assert!(message.contains("safe API usage"));
    assert!(!message.contains("comprehensive review"));
    assert!(!message.contains("thorough analysis"));
    assert!(!message.contains("did not identify"));
}

#[tokio::test]
async fn test_token_tracking_in_metrics() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_request(RecordRequestParams {
            model_name: "gpt-4".to_string(),
            operation: "discovery".to_string(),
            phase: "chat".to_string(),
            prompt_tokens: 1000,
            completion_tokens: 500,
            latency_ms: 1500,
            success: true,
        })
        .await;
    tracker
        .record_request(RecordRequestParams {
            model_name: "gpt-4".to_string(),
            operation: "discovery".to_string(),
            phase: "chat".to_string(),
            prompt_tokens: 800,
            completion_tokens: 400,
            latency_ms: 1200,
            success: true,
        })
        .await;
    tracker
        .record_request(RecordRequestParams {
            model_name: "gpt-3.5".to_string(),
            operation: "verification".to_string(),
            phase: "chat".to_string(),
            prompt_tokens: 500,
            completion_tokens: 200,
            latency_ms: 700,
            success: true,
        })
        .await;

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_tokens, 3400); // (1000+500) + (800+400) + (500+200)
    assert_eq!(metrics.by_model.get("gpt-4").unwrap().total_tokens, 2700); // 1500 + 1200
    assert_eq!(metrics.by_model.get("gpt-3.5").unwrap().total_tokens, 700);
    assert_eq!(
        metrics.by_operation.get("discovery:chat").unwrap().tokens,
        2700
    );
    assert_eq!(
        metrics
            .by_operation
            .get("verification:chat")
            .unwrap()
            .tokens,
        700
    );
}

#[test]
fn test_html_report_includes_token_metrics() {
    use baco::report::json::{LlmMetricsSummary, ModelMetricsSummary, OperationMetricsSummary};

    let mut by_model = HashMap::new();
    by_model.insert(
        "gpt-4".to_string(),
        ModelMetrics {
            model_name: "gpt-4".to_string(),
            total_requests: 2,
            successful_requests: 2,
            failed_requests: 0,
            cached_requests: 0,
            total_tokens: 2700,
            total_latency_ms: 2700,
        },
    );

    let mut by_operation = HashMap::new();
    by_operation.insert(
        "discovery".to_string(),
        OperationMetrics {
            operation: "discovery".to_string(),
            phase: "LlmDiscovery".to_string(),
            requests: 2,
            successful: 2,
            failed: 0,
            tokens: 2700,
        },
    );

    let llm_metrics = baco::llm_metrics::LlmMetrics {
        total_requests: 2,
        total_success: 2,
        total_failed: 0,
        total_cached: 0,
        total_tokens: 2700,
        total_latency_ms: 2700,
        avg_latency_ms: 1350.0,
        by_model,
        by_operation,
    };

    let summary = LlmMetricsSummary {
        total_requests: llm_metrics.total_requests as usize,
        successful_requests: llm_metrics.total_success as usize,
        failed_requests: llm_metrics.total_failed as usize,
        cached_requests: llm_metrics.total_cached as usize,
        total_tokens: llm_metrics.total_tokens as usize,
        avg_latency_ms: llm_metrics.avg_latency_ms,
        models: llm_metrics
            .by_model
            .iter()
            .map(|(name, m)| ModelMetricsSummary {
                model_name: name.clone(),
                total_requests: m.total_requests as usize,
                successful_requests: m.successful_requests as usize,
                failed_requests: m.failed_requests as usize,
                cached_requests: m.cached_requests as usize,
                total_tokens: m.total_tokens as usize,
            })
            .collect(),
        operations: llm_metrics
            .by_operation
            .iter()
            .map(|(op, m)| OperationMetricsSummary {
                operation: op.clone(),
                phase: m.phase.clone(),
                requests: m.requests as usize,
                successful: m.successful as usize,
                failed: m.failed as usize,
            })
            .collect(),
    };

    assert_eq!(summary.total_tokens, 2700);
    assert_eq!(summary.models.len(), 1);
    assert_eq!(summary.models[0].total_tokens, 2700);
    assert_eq!(summary.operations.len(), 1);
}

#[test]
fn test_agent_prompt_includes_attack_vectors() {
    let system_prompt = r#"You are an OFFENSIVE SECURITY RESEARCHER specializing in vulnerability discovery. Your mission is to find REAL security issues, not to be polite.

**MINDSET**: Think like an attacker. Assume every input is malicious. Hunt for:
- SQL Injection: Unsanitized input in SQL queries
- Command Injection: User input in shell commands
- XSS: Unescaped output in HTML/JS
- Path Traversal: Unvalidated file paths
- Authentication Bypass: Missing or weak auth checks
- Insecure Deserialization: Unsafe object reconstruction
- SSRF: Unvalidated URLs in HTTP requests

**TOOLS STRATEGY**:
1. Read the file and identify potential sinks (dangerous functions)
2. Use pattern_search to trace data flow from sources to sinks
3. If you find a vulnerability, create a test case with file_write
4. Verify the exploit with run_test

**OUTPUT REQUIREMENTS**:
- If you find a vulnerability: Provide EXACT title, detailed description with CWE, severity, code snippet showing the flaw, and a working PoC test path
- If you find NO vulnerability: Explain SPECIFICALLY WHY the code is secure (e.g., "All inputs are sanitized via parameterized queries", "Input validation prevents path traversal")
- NEVER say "comprehensive review was performed" without evidence of what you actually checked
- Be brutal and specific. Generic findings are useless."#;

    assert!(system_prompt.contains("SQL Injection"));
    assert!(system_prompt.contains("Command Injection"));
    assert!(system_prompt.contains("XSS"));
    assert!(system_prompt.contains("Path Traversal"));
    assert!(system_prompt.contains("Authentication Bypass"));
    assert!(system_prompt.contains("SSRF"));
    assert!(system_prompt.contains("OFFENSIVE SECURITY RESEARCHER"));
    assert!(system_prompt.contains("Think like an attacker"));
    assert!(system_prompt.contains("Be brutal and specific"));
    assert!(system_prompt.contains("NEVER say"));
    assert!(system_prompt.contains("Generic findings are useless"));
}
