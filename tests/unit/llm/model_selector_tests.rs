//! Round-robin selector tests for ModelSelector
//!
//! Tests cover:
//! 1. Round-robin selection with 3+ models
//! 2. Empty models array fallback
//! 3. Single model case
//! 4. Selector state reset behavior
//! 5. Concurrent selector instances
//! 6. Model selection after exhaustion
//! 7. Weighted selection (if applicable)
//! 8. Model order preservation

use baco::llm::ModelSelector;
use std::sync::Arc;
use std::thread;

// ============================================================================
// Test 1: Round-robin selection with 3+ models
// ============================================================================

#[test]
fn test_round_robin_selection_with_three_models() {
    let selector = ModelSelector::new(vec![
        "model-a".to_string(),
        "model-b".to_string(),
        "model-c".to_string(),
    ]);

    // Verify round-robin rotation is correct
    assert_eq!(selector.next(), Some("model-a".to_string()));
    assert_eq!(selector.next(), Some("model-b".to_string()));
    assert_eq!(selector.next(), Some("model-c".to_string()));
    // Should cycle back to start
    assert_eq!(selector.next(), Some("model-a".to_string()));
    assert_eq!(selector.next(), Some("model-b".to_string()));
    assert_eq!(selector.next(), Some("model-c".to_string()));
}

// ============================================================================
// Test 2: Empty models array fallback
// ============================================================================

#[test]
fn test_empty_models_array_fallback() {
    let selector = ModelSelector::new(vec![]);

    // Should return None for empty array
    assert!(selector.next().is_none());
    assert!(selector.next().is_none());

    // all_models should return empty vector
    assert!(selector.all_models().is_empty());
}

// ============================================================================
// Test 3: Single model case
// ============================================================================

#[test]
fn test_single_model_case() {
    let selector = ModelSelector::new(vec!["single-model".to_string()]);

    // Should always return the same model
    assert_eq!(selector.next(), Some("single-model".to_string()));
    assert_eq!(selector.next(), Some("single-model".to_string()));
    assert_eq!(selector.next(), Some("single-model".to_string()));

    // Verify model count
    assert_eq!(selector.all_models().len(), 1);
    assert_eq!(selector.all_models()[0], "single-model");
}

// ============================================================================
// Test 4: Selector state reset behavior
// ============================================================================

#[test]
fn test_selector_state_reset_behavior() {
    // Note: ModelSelector doesn't have explicit reset, but we test that
    // it continues cycling correctly (implicit "reset" via modulo)
    let selector = ModelSelector::new(vec!["model-1".to_string(), "model-2".to_string()]);

    // Consume many selections
    for i in 0..1000 {
        let model = selector.next().unwrap();
        // Should alternate between model-1 and model-2
        if i % 2 == 0 {
            assert_eq!(model, "model-1");
        } else {
            assert_eq!(model, "model-2");
        }
    }

    // After 1000 calls (even number), should be back at model-1
    assert_eq!(selector.next(), Some("model-1".to_string()));
}

// ============================================================================
// Test 5: Concurrent selector instances
// ============================================================================

#[test]
fn test_concurrent_selector_instances() {
    let selector = Arc::new(ModelSelector::new(vec![
        "concurrent-a".to_string(),
        "concurrent-b".to_string(),
        "concurrent-c".to_string(),
    ]));

    let mut handles = vec![];

    // Spawn multiple threads each making selections
    for thread_id in 0..10 {
        let selector_clone = Arc::clone(&selector);
        handles.push(thread::spawn(move || {
            let mut results = vec![];
            // Each thread makes 5 selections
            for _ in 0..5 {
                if let Some(model) = selector_clone.next() {
                    results.push((thread_id, model));
                }
            }
            results
        }));
    }

    // Collect all results
    let all_results: Vec<_> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();

    // Should have exactly 50 results (10 threads × 5 selections)
    assert_eq!(all_results.len(), 50);

    // All results should be valid models
    for (_, model) in &all_results {
        assert!(
            model == "concurrent-a" || model == "concurrent-b" || model == "concurrent-c",
            "Invalid model: {}",
            model
        );
    }
}

// ============================================================================
// Test 6: Model selection after exhaustion
// ============================================================================

#[test]
fn test_model_selection_after_exhaustion() {
    let selector = ModelSelector::new(vec!["exhaust-1".to_string(), "exhaust-2".to_string()]);

    // First round
    assert_eq!(selector.next(), Some("exhaust-1".to_string()));
    assert_eq!(selector.next(), Some("exhaust-2".to_string()));

    // Second round (after "exhaustion" of first cycle)
    assert_eq!(selector.next(), Some("exhaust-1".to_string()));
    assert_eq!(selector.next(), Some("exhaust-2".to_string()));

    // Third round
    assert_eq!(selector.next(), Some("exhaust-1".to_string()));
    assert_eq!(selector.next(), Some("exhaust-2".to_string()));

    // Should continue cycling indefinitely (no true exhaustion)
    for _ in 0..100 {
        assert!(selector.next().is_some());
    }
}

// ============================================================================
// Test 7: Weighted selection (if applicable)
// ============================================================================

#[test]
fn test_weighted_selection_not_applicable() {
    // Note: Current ModelSelector implementation uses simple round-robin
    // without weights. This test verifies the basic round-robin behavior.
    let selector = ModelSelector::new(vec!["weighted-a".to_string(), "weighted-b".to_string()]);

    // Verify round-robin pattern returns both models (order may vary due to AtomicUsize)
    let first = selector.next();
    let second = selector.next();
    let third = selector.next();
    let fourth = selector.next();

    // Should alternate between the two models
    assert!(first == Some("weighted-a".to_string()) || first == Some("weighted-b".to_string()));
    assert!(second == Some("weighted-a".to_string()) || second == Some("weighted-b".to_string()));
    assert_ne!(first, third); // Every other call should be the same
    assert_ne!(second, fourth);
}

// ============================================================================
// Test 8: Model order preservation
// ============================================================================

#[test]
fn test_model_order_preservation() {
    let models = vec![
        "first".to_string(),
        "second".to_string(),
        "third".to_string(),
        "fourth".to_string(),
        "fifth".to_string(),
    ];

    let selector = ModelSelector::new(models.clone());

    // Verify all_models preserves order
    let retrieved = selector.all_models();
    assert_eq!(retrieved.len(), 5);
    assert_eq!(retrieved, models);

    // Verify selection order matches insertion order
    assert_eq!(selector.next(), Some("first".to_string()));
    assert_eq!(selector.next(), Some("second".to_string()));
    assert_eq!(selector.next(), Some("third".to_string()));
    assert_eq!(selector.next(), Some("fourth".to_string()));
    assert_eq!(selector.next(), Some("fifth".to_string()));

    // Should wrap around to first
    assert_eq!(selector.next(), Some("first".to_string()));
}

// ============================================================================
// Additional helper tests for completeness
// ============================================================================

#[test]
fn test_selector_new_with_various_inputs() {
    // Empty
    let s1 = ModelSelector::new(vec![]);
    assert!(s1.next().is_none());

    // Single
    let s2 = ModelSelector::new(vec!["one".to_string()]);
    assert_eq!(s2.next(), Some("one".to_string()));

    // Many
    let many: Vec<String> = (0..50).map(|i| format!("model-{}", i)).collect();
    let s3 = ModelSelector::new(many);
    assert_eq!(s3.next(), Some("model-0".to_string()));
    assert_eq!(s3.next(), Some("model-1".to_string()));
}

#[test]
fn test_selector_deterministic_behavior() {
    // Create multiple selectors with same input
    let models = vec!["a".to_string(), "b".to_string(), "c".to_string()];

    let results: Vec<Vec<Option<String>>> = (0..5)
        .map(|_| {
            let selector = ModelSelector::new(models.clone());
            (0..6).map(|_| selector.next()).collect()
        })
        .collect();

    // All selectors should produce identical results
    for result in &results[1..] {
        assert_eq!(&results[0], result);
    }
}
