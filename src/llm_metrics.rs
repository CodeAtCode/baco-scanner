//! LLM metrics tracking module
//!
//! Provides thread-safe tracking of LLM usage statistics across all analysis phases.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Metrics for a specific LLM model
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelMetrics {
    pub model_name: String,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub cached_requests: u64,
    pub total_tokens: u64,
    pub total_latency_ms: u64,
}

/// Metrics for a specific operation/phase
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OperationMetrics {
    pub operation: String,
    pub phase: String,
    pub requests: u64,
    pub successful: u64,
    pub failed: u64,
    pub tokens: u64,
}

/// Aggregated LLM metrics for the entire scan
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LlmMetrics {
    pub total_requests: u64,
    pub total_success: u64,
    pub total_failed: u64,
    pub total_cached: u64,
    pub total_tokens: u64,
    pub total_latency_ms: u64,
    pub avg_latency_ms: f64,
    pub by_model: HashMap<String, ModelMetrics>,
    pub by_operation: HashMap<String, OperationMetrics>,
}

/// Thread-safe tracker for LLM metrics
#[derive(Debug, Clone, Default)]
pub struct LlmMetricsTracker {
    inner: Arc<RwLock<LlmMetrics>>,
}

impl LlmMetricsTracker {
    /// Create a new empty tracker
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(LlmMetrics::default())),
        }
    }

    /// Record a single LLM request
    pub async fn record_request(&self, params: RecordRequestParams) {
        let mut metrics = self.inner.write().await;

        metrics.total_requests += 1;
        metrics.total_tokens += params.prompt_tokens + params.completion_tokens;
        metrics.total_latency_ms += params.latency_ms;

        if params.success {
            metrics.total_success += 1;
        } else {
            metrics.total_failed += 1;
        }

        // Update model metrics
        let model_entry = metrics
            .by_model
            .entry(params.model_name.clone())
            .or_insert_with(|| ModelMetrics {
                model_name: params.model_name.clone(),
                ..Default::default()
            });

        model_entry.total_requests += 1;
        if params.success {
            model_entry.successful_requests += 1;
        } else {
            model_entry.failed_requests += 1;
        }
        model_entry.total_tokens += params.prompt_tokens + params.completion_tokens;
        model_entry.total_latency_ms += params.latency_ms;

        // Update operation metrics
        let op_key = format!("{}:{}", params.operation, params.phase);
        let op_entry = metrics
            .by_operation
            .entry(op_key.clone())
            .or_insert_with(|| OperationMetrics {
                operation: params.operation.clone(),
                phase: params.phase.clone(),
                ..Default::default()
            });

        op_entry.requests += 1;
        if params.success {
            op_entry.successful += 1;
        } else {
            op_entry.failed += 1;
        }
        op_entry.tokens += params.prompt_tokens + params.completion_tokens;
    }

    /// Record a cached request (from LLM cache)
    pub async fn record_cached_request(
        &self,
        model_name: &str,
        operation: &str,
        phase: &str,
        tokens: u64,
    ) {
        let mut metrics = self.inner.write().await;

        metrics.total_requests += 1;
        metrics.total_success += 1;
        metrics.total_cached += 1;
        metrics.total_tokens += tokens;

        let model_entry = metrics
            .by_model
            .entry(model_name.to_string())
            .or_insert_with(|| ModelMetrics {
                model_name: model_name.to_string(),
                ..Default::default()
            });

        model_entry.total_requests += 1;
        model_entry.successful_requests += 1;
        model_entry.cached_requests += 1;
        model_entry.total_tokens += tokens;

        let op_key = format!("{}:{}", operation, phase);
        let op_entry = metrics
            .by_operation
            .entry(op_key.clone())
            .or_insert_with(|| OperationMetrics {
                operation: operation.to_string(),
                phase: phase.to_string(),
                ..Default::default()
            });

        op_entry.requests += 1;
        op_entry.successful += 1;
        op_entry.tokens += tokens;
    }

    /// Finalize and return the metrics
    pub async fn finalize(&self) -> LlmMetrics {
        let metrics = self.inner.read().await;

        let mut final_metrics = (*metrics).clone();

        if metrics.total_requests > 0 {
            final_metrics.avg_latency_ms =
                metrics.total_latency_ms as f64 / metrics.total_requests as f64;
        }

        final_metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_llm_metrics_tracking() {
        let tracker = LlmMetricsTracker::new();

        // Simulate LLM calls
        tracker
            .record_request(RecordRequestParams {
                model_name: "mistral-small".to_string(),
                operation: "chat".to_string(),
                phase: "LlmDiscovery".to_string(),
                prompt_tokens: 100,
                completion_tokens: 200,
                latency_ms: 300,
                success: true,
            })
            .await;
        tracker
            .record_request(RecordRequestParams {
                model_name: "mistral-small".to_string(),
                operation: "chat".to_string(),
                phase: "LlmDiscovery".to_string(),
                prompt_tokens: 100,
                completion_tokens: 200,
                latency_ms: 300,
                success: true,
            })
            .await;
        tracker
            .record_request(RecordRequestParams {
                model_name: "mistral-small".to_string(),
                operation: "chat".to_string(),
                phase: "LlmDiscovery".to_string(),
                prompt_tokens: 100,
                completion_tokens: 200,
                latency_ms: 300,
                success: false,
            })
            .await;
        tracker
            .record_cached_request("mistral-small", "chat", "LlmDiscovery", 100)
            .await;

        let metrics = tracker.finalize().await;

        assert_eq!(metrics.total_requests, 4); // 3 actual + 1 cached
        assert_eq!(metrics.total_success, 3);
        assert_eq!(metrics.total_failed, 1);
        assert_eq!(metrics.total_cached, 1);
        assert_eq!(metrics.total_tokens, 1000); // 300 + 300 + 300 + 100

        assert_eq!(metrics.by_model.len(), 1);
        let model_metrics = metrics.by_model.get("mistral-small").unwrap();
        assert_eq!(model_metrics.total_requests, 4);
        assert_eq!(model_metrics.successful_requests, 3);
        assert_eq!(model_metrics.failed_requests, 1);
        assert_eq!(model_metrics.cached_requests, 1);
        assert_eq!(model_metrics.total_tokens, 1000);

        assert_eq!(metrics.by_operation.len(), 1);
        let op_metrics = metrics.by_operation.get("chat:LlmDiscovery").unwrap();
        assert_eq!(op_metrics.requests, 4);
        assert_eq!(op_metrics.successful, 3);
        assert_eq!(op_metrics.failed, 1);
        assert_eq!(op_metrics.tokens, 1000);
    }

    #[tokio::test]
    async fn test_llm_metrics_multiple_models() {
        let tracker = LlmMetricsTracker::new();

        tracker
            .record_request(RecordRequestParams {
                model_name: "model-a".to_string(),
                operation: "chat".to_string(),
                phase: "LlmDiscovery".to_string(),
                prompt_tokens: 50,
                completion_tokens: 50,
                latency_ms: 1000,
                success: true,
            })
            .await;
        tracker
            .record_request(RecordRequestParams {
                model_name: "model-b".to_string(),
                operation: "chat".to_string(),
                phase: "LlmVerification".to_string(),
                prompt_tokens: 100,
                completion_tokens: 100,
                latency_ms: 2000,
                success: true,
            })
            .await;

        let metrics = tracker.finalize().await;

        assert_eq!(metrics.by_model.len(), 2);
        assert_eq!(metrics.by_model.get("model-a").unwrap().total_requests, 1);
        assert_eq!(metrics.by_model.get("model-b").unwrap().total_requests, 1);

        assert_eq!(metrics.by_operation.len(), 2);
        assert!(metrics.by_operation.contains_key("chat:LlmDiscovery"));
        assert!(metrics.by_operation.contains_key("chat:LlmVerification"));
    }

    #[tokio::test]
    async fn test_llm_metrics_zero_requests() {
        let tracker = LlmMetricsTracker::new();
        let metrics = tracker.finalize().await;

        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.avg_latency_ms, 0.0);
        assert!(metrics.by_model.is_empty());
        assert!(metrics.by_operation.is_empty());
    }

    #[tokio::test]
    async fn test_llm_metrics_serialization() {
        let tracker = LlmMetricsTracker::new();
        tracker
            .record_request(RecordRequestParams {
                model_name: "test-model".to_string(),
                operation: "chat".to_string(),
                phase: "TestPhase".to_string(),
                prompt_tokens: 100,
                completion_tokens: 200,
                latency_ms: 1500,
                success: true,
            })
            .await;

        let metrics = tracker.finalize().await;

        // Test JSON serialization
        let json = serde_json::to_string_pretty(&metrics).unwrap();
        assert!(json.contains("\"total_requests\""));
        assert!(json.contains("\"successful_requests\""));
        assert!(json.contains("\"failed_requests\""));
        assert!(json.contains("\"cached_requests\""));
        assert!(json.contains("\"total_tokens\""));
        assert!(json.contains("\"avg_latency_ms\""));

        // Test deserialization
        let deserialized: LlmMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_requests, metrics.total_requests);
        assert_eq!(deserialized.total_success, metrics.total_success);
    }
}

/// Parameters for record_request to reduce argument count warning
#[allow(dead_code)]
pub struct RecordRequestParams {
    pub model_name: String,
    pub operation: String,
    pub phase: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub latency_ms: u64,
    pub success: bool,
}
