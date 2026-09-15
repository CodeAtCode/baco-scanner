//! Budget estimator tests

use baco::config::phases::BudgetConfig;

#[test]
fn test_budget_reserve_percent_zero() {
    // When reserve_percent is 0, all budget is available for triage
    let config = BudgetConfig {
        enabled: true,
        max_llm_calls: 100,
        reserve_percent_for_high_risk: 0,
    };

    let reserved = (config.max_llm_calls as f32 * config.reserve_percent_for_high_risk as f32 / 100.0) as usize;
    let available = config.max_llm_calls - reserved;

    assert_eq!(reserved, 0, "0% reserve should reserve 0 calls");
    assert_eq!(available, 100, "All 100 calls should be available");
}

#[test]
fn test_budget_reserve_percent_30() {
    // When reserve_percent is 30, 30% is reserved for high-risk files
    let config = BudgetConfig {
        enabled: true,
        max_llm_calls: 100,
        reserve_percent_for_high_risk: 30,
    };

    let reserved = (config.max_llm_calls as f32 * config.reserve_percent_for_high_risk as f32 / 100.0) as usize;
    let available = config.max_llm_calls - reserved;

    assert_eq!(reserved, 30, "30% of 100 should reserve 30 calls");
    assert_eq!(available, 70, "70 calls should be available for triage");
}

#[test]
fn test_budget_default_disabled() {
    // Default config should be disabled
    let config = BudgetConfig::default();

    assert!(!config.enabled, "Budget should be disabled by default");
    assert_eq!(config.max_llm_calls, 100, "Default max_llm_calls should be 100");
    assert_eq!(
        config.reserve_percent_for_high_risk, 20,
        "Default reserve_percent should be 20"
    );
}

#[test]
fn test_budget_high_risk_residual() {
    // After triage consumes budget, high-risk files should have reserved budget available
    let config = BudgetConfig {
        enabled: true,
        max_llm_calls: 100,
        reserve_percent_for_high_risk: 30,
    };

    let reserved = (config.max_llm_calls as f32 * config.reserve_percent_for_high_risk as f32 / 100.0) as usize;
    let triage_budget = config.max_llm_calls - reserved;

    // Simulate triage using 50 calls
    let triage_used = 50;
    let remaining_after_triage = triage_budget - triage_used;

    assert_eq!(triage_budget, 70, "Triage budget should be 70");
    assert_eq!(remaining_after_triage, 20, "20 calls remaining after triage");
    assert_eq!(reserved, 30, "30 calls reserved for high-risk");
}

#[test]
fn test_budget_calculation_edge_cases() {
    // Test edge cases: very small budget, rounding
    let config_small = BudgetConfig {
        enabled: true,
        max_llm_calls: 10,
        reserve_percent_for_high_risk: 30,
    };

    let reserved_small = (config_small.max_llm_calls as f32 * config_small.reserve_percent_for_high_risk as f32 / 100.0) as usize;
    // 30% of 10 = 3
    assert_eq!(reserved_small, 3, "30% of 10 should round to 3");

    let config_uneven = BudgetConfig {
        enabled: true,
        max_llm_calls: 33,
        reserve_percent_for_high_risk: 30,
    };

    let reserved_uneven = (config_uneven.max_llm_calls as f32 * config_uneven.reserve_percent_for_high_risk as f32 / 100.0) as usize;
    // 30% of 33 = 9.9, truncates to 9
    assert_eq!(reserved_uneven, 9, "30% of 33 should truncate to 9");
}