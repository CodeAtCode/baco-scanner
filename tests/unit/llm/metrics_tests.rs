//! Unit tests for LLM metrics tracking
//!
//! Tests cover:
//! 1. Metrics tracker initialization
//! 2. Request recording (success/failure)
//! 3. Cached request recording
//! 4. Per-model metrics aggregation
//! 5. Per-operation metrics aggregation
//! 6. Token accounting
//! 7. Latency tracking
//! 8. Positional fallback counting
//! 9. Metrics finalization

use baco::llm::metrics::{
    LlmMetrics, LlmMetricsTracker, ModelMetrics, OperationMetrics, RecordRequestParams,
};

// ============================================================================
// Tracker Initialization Tests
// ============================================================================

#[test]
fn test_metrics_tracker_new_is_empty() {
    let tracker = LlmMetricsTracker::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let metrics = rt.block_on(tracker.finalize());

    assert_eq!(metrics.total_requests, 0);
    assert_eq!(metrics.total_success, 0);
    assert_eq!(metrics.total_failed, 0);
    assert!(metrics.by_model.is_empty());
    assert!(metrics.by_operation.is_empty());
}

// ============================================================================
// Request Recording Tests
// ============================================================================

#[tokio::test]
async fn test_record_request_success() {
    let tracker = LlmMetricsTracker::new();

    let params = RecordRequestParams {
        model_name: "gpt-4".to_string(),
        operation: "chat".to_string(),
        phase: "analysis".to_string(),
        prompt_tokens: 100,
        completion_tokens: 50,
        latency_ms: 500,
        success: true,
    };

    tracker.record_request(params).await;
    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_requests, 1);
    assert_eq!(metrics.total_success, 1);
    assert_eq!(metrics.total_failed, 0);
    assert_eq!(metrics.total_tokens, 150);
    assert_eq!(metrics.total_latency_ms, 500);
}

#[tokio::test]
async fn test_record_request_failure() {
    let tracker = LlmMetricsTracker::new();

    let params = RecordRequestParams {
        model_name: "gpt-4".to_string(),
        operation: "chat".to_string(),
        phase: "analysis".to_string(),
        prompt_tokens: 100,
        completion_tokens: 50,
        latency_ms: 1000,
        success: false,
    };

    tracker.record_request(params).await;
    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_requests, 1);
    assert_eq!(metrics.total_success, 0);
    assert_eq!(metrics.total_failed, 1);
}

// ============================================================================
// Cached Request Tests
// ============================================================================

#[tokio::test]
async fn test_record_cached_request() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_cached_request("gpt-4", "chat", "analysis", 150)
        .await;

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_requests, 1);
    assert_eq!(metrics.total_success, 1);
    assert_eq!(metrics.total_cached, 1);
    assert_eq!(metrics.total_tokens, 150);
}

#[tokio::test]
async fn test_record_cached_request_updates_model_metrics() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_cached_request("claude-3", "chat_with_tools", "verification", 200)
        .await;

    let metrics = tracker.finalize().await;

    let model_metrics = metrics.by_model.get("claude-3").unwrap();
    assert_eq!(model_metrics.model_name, "claude-3");
    assert_eq!(model_metrics.total_requests, 1);
    assert_eq!(model_metrics.cached_requests, 1);
    assert_eq!(model_metrics.total_tokens, 200);
}

// ============================================================================
// Per-Model Aggregation Tests
// ============================================================================

#[tokio::test]
async fn test_multiple_models_aggregation() {
    let tracker = LlmMetricsTracker::new();

    // Record requests for different models
    tracker
        .record_request(RecordRequestParams {
            model_name: "gpt-4".to_string(),
            operation: "chat".to_string(),
            phase: "analysis".to_string(),
            prompt_tokens: 100,
            completion_tokens: 50,
            latency_ms: 500,
            success: true,
        })
        .await;

    tracker
        .record_request(RecordRequestParams {
            model_name: "gpt-4".to_string(),
            operation: "chat".to_string(),
            phase: "analysis".to_string(),
            prompt_tokens: 200,
            completion_tokens: 100,
            latency_ms: 800,
            success: true,
        })
        .await;

    tracker
        .record_request(RecordRequestParams {
            model_name: "claude-3".to_string(),
            operation: "chat".to_string(),
            phase: "analysis".to_string(),
            prompt_tokens: 150,
            completion_tokens: 75,
            latency_ms: 600,
            success: true,
        })
        .await;

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_requests, 3);

    let gpt4_metrics = metrics.by_model.get("gpt-4").unwrap();
    assert_eq!(gpt4_metrics.total_requests, 2);
    assert_eq!(gpt4_metrics.total_tokens, 450);
    assert_eq!(gpt4_metrics.total_latency_ms, 1300);

    let claude_metrics = metrics.by_model.get("claude-3").unwrap();
    assert_eq!(claude_metrics.total_requests, 1);
    assert_eq!(claude_metrics.total_tokens, 225);
}

// ============================================================================
// Per-Operation Aggregation Tests
// ============================================================================

#[tokio::test]
async fn test_operation_metrics_aggregation() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_request(RecordRequestParams {
            model_name: "gpt-4".to_string(),
            operation: "chat".to_string(),
            phase: "analysis".to_string(),
            prompt_tokens: 100,
            completion_tokens: 50,
            latency_ms: 500,
            success: true,
        })
        .await;

    tracker
        .record_request(RecordRequestParams {
            model_name: "gpt-4".to_string(),
            operation: "chat".to_string(),
            phase: "verification".to_string(),
            prompt_tokens: 200,
            completion_tokens: 100,
            latency_ms: 700,
            success: true,
        })
        .await;

    let metrics = tracker.finalize().await;

    // Should have two operation entries: "chat:analysis" and "chat:verification"
    assert_eq!(metrics.by_operation.len(), 2);

    let analysis_op = metrics.by_operation.get("chat:analysis").unwrap();
    assert_eq!(analysis_op.operation, "chat");
    assert_eq!(analysis_op.phase, "analysis");
    assert_eq!(analysis_op.requests, 1);
    assert_eq!(analysis_op.prompt_tokens, 100);
    assert_eq!(analysis_op.completion_tokens, 50);

    let verification_op = metrics.by_operation.get("chat:verification").unwrap();
    assert_eq!(verification_op.requests, 1);
    assert_eq!(verification_op.prompt_tokens, 200);
}

// ============================================================================
// Latency and Average Calculations
// ============================================================================

#[tokio::test]
async fn test_avg_latency_calculation() {
    let tracker = LlmMetricsTracker::new();

    tracker
        .record_request(RecordRequestParams {
            model_name: "gpt-4".to_string(),
            operation: "chat".to_string(),
            phase: "analysis".to_string(),
            prompt_tokens: 100,
            completion_tokens: 50,
            latency_ms: 400,
            success: true,
        })
        .await;

    tracker
        .record_request(RecordRequestParams {
            model_name: "gpt-4".to_string(),
            operation: "chat".to_string(),
            phase: "analysis".to_string(),
            prompt_tokens: 100,
            completion_tokens: 50,
            latency_ms: 600,
            success: true,
        })
        .await;

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_latency_ms, 1000);
    assert_eq!(metrics.avg_latency_ms, 500.0);
}

#[tokio::test]
async fn test_avg_latency_zero_requests() {
    let tracker = LlmMetricsTracker::new();
    let metrics = tracker.finalize().await;

    assert_eq!(metrics.avg_latency_ms, 0.0);
}

// ============================================================================
// Positional Fallback Tests
// ============================================================================

#[tokio::test]
async fn test_record_positional_fallback() {
    let tracker = LlmMetricsTracker::new();

    tracker.record_positional_fallback(3).await;
    tracker.record_positional_fallback(5).await;

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.positional_fallbacks, 8);
}

// ============================================================================
// Mixed Success/Failure Tests
// ============================================================================

#[tokio::test]
async fn test_mixed_success_failure_tracking() {
    let tracker = LlmMetricsTracker::new();

    // 3 successes, 2 failures
    for i in 0..5 {
        tracker
            .record_request(RecordRequestParams {
                model_name: "gpt-4".to_string(),
                operation: "chat".to_string(),
                phase: "analysis".to_string(),
                prompt_tokens: 100,
                completion_tokens: 50,
                latency_ms: 500,
                success: i < 3,
            })
            .await;
    }

    let metrics = tracker.finalize().await;

    assert_eq!(metrics.total_requests, 5);
    assert_eq!(metrics.total_success, 3);
    assert_eq!(metrics.total_failed, 2);
}

// ============================================================================
// ModelMetrics Structure Tests
// ============================================================================

#[test]
fn test_model_metrics_default() {
    let metrics = ModelMetrics::default();

    assert!(metrics.model_name.is_empty());
    assert_eq!(metrics.total_requests, 0);
    assert_eq!(metrics.successful_requests, 0);
    assert_eq!(metrics.failed_requests, 0);
    assert_eq!(metrics.total_tokens, 0);
}

#[test]
fn test_operation_metrics_default() {
    let metrics = OperationMetrics::default();

    assert!(metrics.operation.is_empty());
    assert!(metrics.phase.is_empty());
    assert_eq!(metrics.requests, 0);
    assert_eq!(metrics.tokens, 0);
}

// ============================================================================
// LlmMetrics Structure Tests
// ============================================================================

#[test]
fn test_llm_metrics_default() {
    let metrics = LlmMetrics::default();

    assert_eq!(metrics.total_requests, 0);
    assert_eq!(metrics.total_success, 0);
    assert_eq!(metrics.total_failed, 0);
    assert_eq!(metrics.total_cached, 0);
    assert_eq!(metrics.total_tokens, 0);
    assert!(metrics.by_model.is_empty());
    assert!(metrics.by_operation.is_empty());
}