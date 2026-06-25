use std::sync::Arc;
use tokio::sync::Semaphore;

/// Rate limiter for LLM API calls using a semaphore-based approach.
/// Prevents exceeding provider rate limits by limiting concurrent requests.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    semaphore: Arc<Semaphore>,
    max_concurrent: usize,
}

impl RateLimiter {
    /// Create a new rate limiter with the specified maximum concurrent requests.
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_concurrent,
        }
    }

    /// Acquire a permit before making an LLM call.
    /// This will block until a permit is available.
    pub async fn acquire(&self) -> Result<tokio::sync::SemaphorePermit<'_>, String> {
        self.semaphore
            .acquire()
            .await
            .map_err(|e| format!("Failed to acquire rate limiter permit: {}", e))
    }

    /// Try to acquire a permit without blocking.
    /// Returns None if no permit is available.
    pub fn try_acquire(&self) -> Option<tokio::sync::SemaphorePermit<'_>> {
        self.semaphore.try_acquire().ok()
    }

    /// Get the maximum number of concurrent requests allowed.
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Get the current number of available permits.
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        // Default to 3 concurrent requests (conservative default for most LLM providers)
        Self::new(3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
