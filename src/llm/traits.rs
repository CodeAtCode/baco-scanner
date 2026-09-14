/// Unified LLM client trait for async chat operations.
///
/// This trait provides a common interface for LLM clients used across the codebase,
/// enabling testing with mock implementations and future client swapping.
///
/// NOTE: This trait was unified from `AsyncLlmClient` (from llm_verification.rs) and
/// `LlmChatClient` (from llm.rs). Their shapes are identical, but a true trait alias
/// is not stable in Rust. Both trait names are kept here for backward compatibility
/// during the transition to the client-move stage (Stage B).
#[allow(async_fn_in_trait)]
#[cfg_attr(test, mockall::automock)]
pub trait AsyncLlmClient: Send + Sync {
    async fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponseWithModel, ScanError>;
}

/// Legacy trait name - kept separate from AsyncLlmClient for backward compatibility.
///
/// DEPRECATED: Use `AsyncLlmClient` instead. This exists only to maintain existing
/// import paths during the unification transition. The actual trait implementation
/// should migrate to AsyncLlmClient in the client-move stage (Stage B).
///
/// SHAPE DIFFERENCE: None - this trait has the exact same method signature as
/// `AsyncLlmClient`. The separation is purely for backward compatibility during
/// the transition; no functional difference exists.
#[allow(async_fn_in_trait)]
#[cfg_attr(test, mockall::automock)]
pub trait LlmChatClient: Send + Sync {
    async fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponseWithModel, ScanError>;
}

// Re-export types needed by the traits
pub use crate::error::ScanError;
pub use super::{ChatMessage, ChatResponseWithModel};
