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
