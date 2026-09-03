//! Unit tests for src/rate_limiter.rs
//!
//! Tests cover rate limiting logic, token bucket behavior,
//! and concurrency control.

use baco::rate_limiter::RateLimiter;

// ============================================================================
// RateLimiter::new() Tests
// ============================================================================

#[tokio::test]
async fn test_rate_limiter_new_sets_correct_capacity() {
    let limiter = RateLimiter::new(5);

    assert_eq!(limiter.max_concurrent(), 5);
    assert_eq!(limiter.available_permits(), 5);
}

#[tokio::test]
async fn test_rate_limiter_new_with_zero_capacity() {
    let limiter = RateLimiter::new(0);

    assert_eq!(limiter.max_concurrent(), 0);
    assert_eq!(limiter.available_permits(), 0);
}

#[tokio::test]
async fn test_rate_limiter_new_with_large_capacity() {
    let limiter = RateLimiter::new(1000);

    assert_eq!(limiter.max_concurrent(), 1000);
    assert_eq!(limiter.available_permits(), 1000);
}

// ============================================================================
// RateLimiter::default() Tests
// ============================================================================

#[tokio::test]
async fn test_rate_limiter_default_capacity() {
    let limiter = RateLimiter::default();

    assert_eq!(limiter.max_concurrent(), 3);
    assert_eq!(limiter.available_permits(), 3);
}

// ============================================================================
// RateLimiter::acquire() Tests
// ============================================================================

#[tokio::test]
async fn test_acquire_gets_permit() {
    let limiter = RateLimiter::new(5);

    let _permit = limiter.acquire().await.unwrap();

    assert_eq!(limiter.available_permits(), 4);

    drop(_permit);
    assert_eq!(limiter.available_permits(), 5);
}

#[tokio::test]
async fn test_acquire_exhausts_permits() {
    let limiter = RateLimiter::new(3);

    let permit1 = limiter.acquire().await.unwrap();
    let permit2 = limiter.acquire().await.unwrap();
    let permit3 = limiter.acquire().await.unwrap();

    assert_eq!(limiter.available_permits(), 0);

    drop(permit1);
    assert_eq!(limiter.available_permits(), 1);

    drop(permit2);
    assert_eq!(limiter.available_permits(), 2);

    drop(permit3);
    assert_eq!(limiter.available_permits(), 3);
}

// ============================================================================
// RateLimiter::try_acquire() Tests
// ============================================================================

#[tokio::test]
async fn test_try_acquire_succeeds_when_permits_available() {
    let limiter = RateLimiter::new(5);

    let permit = limiter.try_acquire();

    assert!(permit.is_some());
    assert_eq!(limiter.available_permits(), 4);
}

#[tokio::test]
async fn test_try_acquire_returns_none_when_no_permits() {
    let limiter = RateLimiter::new(2);

    let _permit1 = limiter.acquire().await.unwrap();
    let _permit2 = limiter.acquire().await.unwrap();

    let result = limiter.try_acquire();

    assert!(result.is_none());
}

#[tokio::test]
async fn test_try_acquire_succeeds_after_drop() {
    let limiter = RateLimiter::new(1);

    let _permit1 = limiter.acquire().await.unwrap();
    assert!(limiter.try_acquire().is_none());

    drop(_permit1);

    assert!(limiter.try_acquire().is_some());
}

#[tokio::test]
async fn test_try_acquire_with_zero_capacity() {
    let limiter = RateLimiter::new(0);

    let result = limiter.try_acquire();

    assert!(result.is_none());
}

// ============================================================================
// RateLimiter::available_permits() Tests
// ============================================================================

#[tokio::test]
async fn test_available_permits_initial_value() {
    let limiter = RateLimiter::new(10);

    assert_eq!(limiter.available_permits(), 10);
}

#[tokio::test]
async fn test_available_permits_decreases_with_acquire() {
    let limiter = RateLimiter::new(5);

    let _permit = limiter.acquire().await.unwrap();

    assert_eq!(limiter.available_permits(), 4);
}

#[tokio::test]
async fn test_available_permits_increases_with_drop() {
    let limiter = RateLimiter::new(3);

    let permit1 = limiter.acquire().await.unwrap();
    let permit2 = limiter.acquire().await.unwrap();

    assert_eq!(limiter.available_permits(), 1);

    drop(permit1);
    assert_eq!(limiter.available_permits(), 2);

    drop(permit2);
    assert_eq!(limiter.available_permits(), 3);
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_acquire_and_release() {
    let limiter = RateLimiter::new(3);

    // Acquire permits
    let _permit1 = limiter.acquire().await.unwrap();
    let _permit2 = limiter.acquire().await.unwrap();

    assert_eq!(limiter.available_permits(), 1);

    // Release permits
    drop(_permit1);
    drop(_permit2);

    assert_eq!(limiter.available_permits(), 3);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_zero_capacity_limiter() {
    let limiter = RateLimiter::new(0);

    assert_eq!(limiter.max_concurrent(), 0);
    assert_eq!(limiter.available_permits(), 0);
    assert!(limiter.try_acquire().is_none());

    // Acquire should hang, so we use try_acquire which returns None
    let result = limiter.try_acquire();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_single_capacity_limiter() {
    let limiter = RateLimiter::new(1);

    let permit1 = limiter.acquire().await.unwrap();
    assert_eq!(limiter.available_permits(), 0);

    assert!(limiter.try_acquire().is_none());

    drop(permit1);
    assert_eq!(limiter.available_permits(), 1);
}

#[tokio::test]
async fn test_large_capacity_limiter() {
    let limiter = RateLimiter::new(100);

    assert_eq!(limiter.available_permits(), 100);

    let mut permits = vec![];
    for _ in 0..50 {
        permits.push(limiter.acquire().await.unwrap());
    }

    assert_eq!(limiter.available_permits(), 50);

    drop(permits);
    assert_eq!(limiter.available_permits(), 100);
}

// ============================================================================
// Clone Tests
// ============================================================================

#[tokio::test]
async fn test_clone_shares_state() {
    let limiter = RateLimiter::new(5);
    let limiter_clone = limiter.clone();

    let _permit = limiter.acquire().await.unwrap();

    // Clone should see the same available permits
    assert_eq!(limiter_clone.available_permits(), 4);
}

#[tokio::test]
async fn test_multiple_clones() {
    let limiter = RateLimiter::new(3);
    let clone1 = limiter.clone();
    let clone2 = limiter.clone();
    let clone3 = limiter.clone();

    let _permit = clone1.acquire().await.unwrap();

    assert_eq!(limiter.available_permits(), 2);
    assert_eq!(clone2.available_permits(), 2);
    assert_eq!(clone3.available_permits(), 2);
}

// ============================================================================
// Stress Tests
// ============================================================================

#[tokio::test]
async fn test_rapid_acquire_release_cycle() {
    let limiter = RateLimiter::new(10);

    for _ in 0..100 {
        let permit = limiter.acquire().await.unwrap();
        drop(permit);
    }

    assert_eq!(limiter.available_permits(), 10);
}

#[tokio::test]
async fn test_many_concurrent_permits() {
    let limiter = RateLimiter::new(50);
    let mut permits = vec![];

    for _ in 0..50 {
        permits.push(limiter.acquire().await.unwrap());
    }

    assert_eq!(limiter.available_permits(), 0);
    assert!(limiter.try_acquire().is_none());

    drop(permits);
    assert_eq!(limiter.available_permits(), 50);
}
// ============================================================================
// Additional RateLimiter Tests
// ============================================================================

#[tokio::test]
async fn test_rate_limiter_concurrent_requests() {
    let limiter = RateLimiter::new(2);

    // Should be able to acquire 2 permits immediately
    let permit1 = limiter.acquire().await.unwrap();
    let permit2 = limiter.acquire().await.unwrap();

    // Third acquire should block (we'll use try_acquire to test)
    assert!(limiter.try_acquire().is_none());

    // Drop permits
    drop(permit1);
    drop(permit2);

    // Now should be able to acquire again
    assert!(limiter.try_acquire().is_some());
}

#[tokio::test]
async fn test_rate_limiter_default() {
    let limiter = RateLimiter::default();
    assert_eq!(limiter.max_concurrent(), 3);
    assert_eq!(limiter.available_permits(), 3);
}

#[tokio::test]
async fn test_rate_limiter_available_permits() {
    let limiter = RateLimiter::new(5);
    assert_eq!(limiter.available_permits(), 5);

    let _permit = limiter.acquire().await.unwrap();
    assert_eq!(limiter.available_permits(), 4);
}

#[tokio::test]
async fn test_rate_limiter_burst_behavior() {
    let limiter = RateLimiter::new(3);

    let permit1 = limiter.acquire().await.unwrap();
    let permit2 = limiter.acquire().await.unwrap();
    let permit3 = limiter.acquire().await.unwrap();

    assert_eq!(limiter.available_permits(), 0);
    assert!(limiter.try_acquire().is_none());

    drop(permit1);

    assert_eq!(limiter.available_permits(), 1);
    assert!(limiter.try_acquire().is_some());

    drop(permit2);
    drop(permit3);

    assert_eq!(limiter.available_permits(), 3);
}

#[tokio::test]
async fn test_rate_limiter_permit_recovery() {
    let limiter = RateLimiter::new(2);

    let _permit1 = limiter.acquire().await.unwrap();
    let _permit2 = limiter.acquire().await.unwrap();

    assert_eq!(limiter.available_permits(), 0);

    drop(_permit1);

    assert_eq!(limiter.available_permits(), 1);

    drop(_permit2);

    assert_eq!(limiter.available_permits(), 2);
}

#[tokio::test]
async fn test_rate_limiter_zero_capacity() {
    let limiter = RateLimiter::new(0);

    assert_eq!(limiter.available_permits(), 0);
    assert_eq!(limiter.max_concurrent(), 0);

    let result = limiter.try_acquire();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_rate_limiter_large_capacity() {
    let limiter = RateLimiter::new(100);

    assert_eq!(limiter.available_permits(), 100);
    assert_eq!(limiter.max_concurrent(), 100);

    let mut acquired = Vec::new();
    for _ in 0..50 {
        acquired.push(limiter.acquire().await.unwrap());
    }

    assert_eq!(limiter.available_permits(), 50);

    drop(acquired);

    assert_eq!(limiter.available_permits(), 100);
}

#[tokio::test]
async fn test_rate_limiter_try_acquire_behavior() {
    let limiter = RateLimiter::new(2);

    let p1 = limiter.try_acquire();
    assert!(p1.is_some());
    let p2 = limiter.try_acquire();
    assert!(p2.is_some());
    assert!(limiter.try_acquire().is_none());

    drop(p1);
    assert!(limiter.try_acquire().is_some());
}
