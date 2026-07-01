//! Tests for LLM metrics tracking functionality
//!
//! Covers: LlmMetricsTracker, ModelMetrics, OperationMetrics, LlmMetrics

use baco::llm_metrics::{
    LlmMetrics, LlmMetricsTracker, ModelMetrics, OperationMetrics, RecordRequestParams,
};

#[tokio::test]
async fn test_llm_metrics_tracker_new() {
    let tracker = LlmMetricsTracker::new();

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_requests, 0);
    assert_eq!(metrics.total_success, 0);
    assert_eq!(metrics.total_failed, 0);
    assert!(metrics.by_model.is_empty());
    assert!(metrics.by_operation.is_empty());
}

#[tokio::test]
async fn test_record_request_success() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_request(RecordRequestParams {
            model_name: "test-model".to_string(),
            operation: "chat".to_string(),
            phase: "test-phase".to_string(),
            prompt_tokens: 100,
            completion_tokens: 200,
            latency_ms: 500,
            success: true,
        })
        .await;

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_requests, 1);
    assert_eq!(metrics.total_success, 1);
    assert_eq!(metrics.total_failed, 0);
    assert_eq!(metrics.total_tokens, 300);
    assert_eq!(metrics.total_latency_ms, 500);
    assert_eq!(metrics.avg_latency_ms, 500.0);
}

#[tokio::test]
async fn test_record_request_failure() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_request(RecordRequestParams {
            model_name: "test-model".to_string(),
            operation: "chat".to_string(),
            phase: "test-phase".to_string(),
            prompt_tokens: 100,
            completion_tokens: 200,
            latency_ms: 500,
            success: false,
        })
        .await;

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_requests, 1);
    assert_eq!(metrics.total_success, 0);
    assert_eq!(metrics.total_failed, 1);
}

#[tokio::test]
async fn test_record_cached_request() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_cached_request("test-model", "chat", "test-phase", 100)
        .await;

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_requests, 1);
    assert_eq!(metrics.total_success, 1);
    assert_eq!(metrics.total_cached, 1);
    assert_eq!(metrics.total_tokens, 100);
}

#[tokio::test]
async fn test_record_multiple_requests_same_model() {
    let tracker = LlmMetricsTracker::new();

    for _ in 0..5 {
        tracker
            .record_request(RecordRequestParams {
                model_name: "model-a".to_string(),
                operation: "chat".to_string(),
                phase: "phase1".to_string(),
                prompt_tokens: 50,
                completion_tokens: 50,
                latency_ms: 100,
                success: true,
            })
            .await;
    }

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_requests, 5);
    assert_eq!(metrics.total_tokens, 500); // 5 * 100
    assert_eq!(metrics.total_latency_ms, 500); // 5 * 100

    let model_metrics = metrics.by_model.get("model-a").unwrap();
    assert_eq!(model_metrics.total_requests, 5);
    assert_eq!(model_metrics.total_tokens, 500);
}

#[tokio::test]
async fn test_record_multiple_models() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_request(RecordRequestParams {
            model_name: "model-a".to_string(),
            operation: "chat".to_string(),
            phase: "phase1".to_string(),
            prompt_tokens: 100,
            completion_tokens: 100,
            latency_ms: 200,
            success: true,
        })
        .await;

    tracker
        .record_request(RecordRequestParams {
            model_name: "model-b".to_string(),
            operation: "chat".to_string(),
            phase: "phase1".to_string(),
            prompt_tokens: 200,
            completion_tokens: 200,
            latency_ms: 400,
            success: true,
        })
        .await;

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.by_model.len(), 2);
    assert_eq!(metrics.by_model.get("model-a").unwrap().total_requests, 1);
    assert_eq!(metrics.by_model.get("model-b").unwrap().total_requests, 1);
}

#[tokio::test]
async fn test_record_multiple_operations() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_request(RecordRequestParams {
            model_name: "model".to_string(),
            operation: "chat".to_string(),
            phase: "phase1".to_string(),
            prompt_tokens: 100,
            completion_tokens: 100,
            latency_ms: 100,
            success: true,
        })
        .await;

    tracker
        .record_request(RecordRequestParams {
            model_name: "model".to_string(),
            operation: "chat_with_tools".to_string(),
            phase: "phase2".to_string(),
            prompt_tokens: 100,
            completion_tokens: 100,
            latency_ms: 100,
            success: true,
        })
        .await;

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.by_operation.len(), 2);
    assert!(metrics.by_operation.contains_key("chat:phase1"));
    assert!(metrics.by_operation.contains_key("chat_with_tools:phase2"));
}

#[tokio::test]
async fn test_record_mixed_success_failure() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_request(RecordRequestParams {
            model_name: "model".to_string(),
            operation: "chat".to_string(),
            phase: "phase".to_string(),
            prompt_tokens: 100,
            completion_tokens: 100,
            latency_ms: 100,
            success: true,
        })
        .await;

    tracker
        .record_request(RecordRequestParams {
            model_name: "model".to_string(),
            operation: "chat".to_string(),
            phase: "phase".to_string(),
            prompt_tokens: 100,
            completion_tokens: 100,
            latency_ms: 100,
            success: false,
        })
        .await;

    tracker
        .record_request(RecordRequestParams {
            model_name: "model".to_string(),
            operation: "chat".to_string(),
            phase: "phase".to_string(),
            prompt_tokens: 100,
            completion_tokens: 100,
            latency_ms: 100,
            success: true,
        })
        .await;

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_requests, 3);
    assert_eq!(metrics.total_success, 2);
    assert_eq!(metrics.total_failed, 1);
}

#[tokio::test]
async fn test_avg_latency_calculation() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_request(RecordRequestParams {
            model_name: "model".to_string(),
            operation: "chat".to_string(),
            phase: "phase".to_string(),
            prompt_tokens: 0,
            completion_tokens: 0,
            latency_ms: 100,
            success: true,
        })
        .await;

    tracker
        .record_request(RecordRequestParams {
            model_name: "model".to_string(),
            operation: "chat".to_string(),
            phase: "phase".to_string(),
            prompt_tokens: 0,
            completion_tokens: 0,
            latency_ms: 200,
            success: true,
        })
        .await;

    tracker
        .record_request(RecordRequestParams {
            model_name: "model".to_string(),
            operation: "chat".to_string(),
            phase: "phase".to_string(),
            prompt_tokens: 0,
            completion_tokens: 0,
            latency_ms: 300,
            success: true,
        })
        .await;

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.avg_latency_ms, 200.0); // (100 + 200 + 300) / 3
}

#[tokio::test]
async fn test_avg_latency_zero_requests() {
    let tracker = LlmMetricsTracker::new();
    let metrics = tracker.finalize().await;

    assert_eq!(metrics.avg_latency_ms, 0.0);
}

#[test]
fn test_model_metrics_default() {
    let metrics = ModelMetrics::default();

    assert_eq!(metrics.model_name, "");
    assert_eq!(metrics.total_requests, 0);
    assert_eq!(metrics.successful_requests, 0);
    assert_eq!(metrics.failed_requests, 0);
    assert_eq!(metrics.cached_requests, 0);
    assert_eq!(metrics.total_tokens, 0);
    assert_eq!(metrics.total_latency_ms, 0);
}

#[test]
fn test_operation_metrics_default() {
    let metrics = OperationMetrics::default();

    assert_eq!(metrics.operation, "");
    assert_eq!(metrics.phase, "");
    assert_eq!(metrics.requests, 0);
    assert_eq!(metrics.successful, 0);
    assert_eq!(metrics.failed, 0);
    assert_eq!(metrics.tokens, 0);
}

#[test]
fn test_llm_metrics_default() {
    let metrics = LlmMetrics::default();

    assert_eq!(metrics.total_requests, 0);
    assert_eq!(metrics.total_success, 0);
    assert_eq!(metrics.total_failed, 0);
    assert_eq!(metrics.total_cached, 0);
    assert_eq!(metrics.total_tokens, 0);
    assert_eq!(metrics.total_latency_ms, 0);
    assert_eq!(metrics.avg_latency_ms, 0.0);
    assert!(metrics.by_model.is_empty());
    assert!(metrics.by_operation.is_empty());
}

#[tokio::test]
async fn test_metrics_serialization() {
    use serde_json;

    let tracker = LlmMetricsTracker::new();

    tracker
        .record_request(RecordRequestParams {
            model_name: "test-model".to_string(),
            operation: "chat".to_string(),
            phase: "test-phase".to_string(),
            prompt_tokens: 100,
            completion_tokens: 200,
            latency_ms: 500,
            success: true,
        })
        .await;

    let metrics = tracker.finalize().await;

    // Test JSON serialization
    let json = serde_json::to_string(&metrics).unwrap();
    assert!(json.contains("\"total_requests\""));
    assert!(json.contains("\"total_success\""));
    assert!(json.contains("\"total_failed\""));
    assert!(json.contains("\"total_tokens\""));

    // Test deserialization
    let deserialized: LlmMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.total_requests, metrics.total_requests);
    assert_eq!(deserialized.total_success, metrics.total_success);
}

#[tokio::test]
async fn test_record_cached_request_updates_model_metrics() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_cached_request("mistral-small", "chat", "LlmDiscovery", 100)
        .await;

    let metrics = tracker.finalize().await;

    let model_metrics = metrics.by_model.get("mistral-small").unwrap();
    assert_eq!(model_metrics.total_requests, 1);
    assert_eq!(model_metrics.successful_requests, 1);
    assert_eq!(model_metrics.cached_requests, 1);
}

#[tokio::test]
async fn test_record_cached_request_updates_operation_metrics() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_cached_request("model", "chat", "verification", 50)
        .await;

    let metrics = tracker.finalize().await;

    let op_metrics = metrics.by_operation.get("chat:verification").unwrap();
    assert_eq!(op_metrics.requests, 1);
    assert_eq!(op_metrics.successful, 1);
    assert_eq!(op_metrics.tokens, 50);
}

#[tokio::test]
async fn test_complex_metrics_scenario() {
    let tracker = LlmMetricsTracker::new();

    // Simulate a realistic scenario with multiple models, operations, and outcomes
    tracker
        .record_request(RecordRequestParams {
            model_name: "gpt-4".to_string(),
            operation: "chat".to_string(),
            phase: "discovery".to_string(),
            prompt_tokens: 500,
            completion_tokens: 300,
            latency_ms: 2000,
            success: true,
        })
        .await;

    tracker
        .record_request(RecordRequestParams {
            model_name: "gpt-4".to_string(),
            operation: "chat".to_string(),
            phase: "discovery".to_string(),
            prompt_tokens: 500,
            completion_tokens: 300,
            latency_ms: 2500,
            success: false,
        })
        .await;

    tracker
        .record_request(RecordRequestParams {
            model_name: "gpt-3.5".to_string(),
            operation: "chat_with_tools".to_string(),
            phase: "verification".to_string(),
            prompt_tokens: 200,
            completion_tokens: 150,
            latency_ms: 1000,
            success: true,
        })
        .await;

    tracker
        .record_cached_request("gpt-4", "chat", "discovery", 500)
        .await;

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_requests, 4); // 3 real + 1 cached
    assert_eq!(metrics.total_success, 3);
    assert_eq!(metrics.total_failed, 1);
    assert_eq!(metrics.total_cached, 1);
    assert_eq!(metrics.total_tokens, 2650); // 800 + 800 + 350 + 500

    // Check model metrics
    assert_eq!(metrics.by_model.len(), 2);

    let gpt4_metrics = metrics.by_model.get("gpt-4").unwrap();
    assert_eq!(gpt4_metrics.total_requests, 3);
    assert_eq!(gpt4_metrics.successful_requests, 2);
    assert_eq!(gpt4_metrics.failed_requests, 1);
    assert_eq!(gpt4_metrics.cached_requests, 1);

    let gpt35_metrics = metrics.by_model.get("gpt-3.5").unwrap();
    assert_eq!(gpt35_metrics.total_requests, 1);
    assert_eq!(gpt35_metrics.successful_requests, 1);

    // Check operation metrics
    assert_eq!(metrics.by_operation.len(), 3);
    assert!(metrics.by_operation.contains_key("chat:discovery"));
    assert!(metrics
        .by_operation
        .contains_key("chat_with_tools:verification"));
}
