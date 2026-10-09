//! The batching guard is load-bearing, and nothing asserted it.
//!
//! `verify_findings_batched` returns early when `batch_size <= 1`. That `||` is
//! what keeps a batch size of zero from reaching the loop, where the cursor would
//! never advance. A mutation run reported changing that `||` to `&&` as a
//! survivor and classified it as unreachable stub; it is not. With `&&`, a batch
//! size of zero over a non-empty finding list skips the guard and enters the
//! loop, which never terminates.
//!
//! A triage report put this in the same bucket as three genuinely dead branches.
//! It was not one of them, and it was the only one on the list that could hang
//! the process.

use baco::error::ScanError;
use baco::findings::{VerificationStatus, VulnerabilityFinding};
use baco::llm::{ChatMessage, ChatResponseWithModel, LlmChatClient};
use baco::scanner::phases::llm_phases::verification::verify_findings_batched;
use std::collections::HashMap;

/// Records whether the loop was entered. A batch size of zero must never reach
/// the model, because entering the loop is what hangs.
struct MustNotBeCalled {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl LlmChatClient for MustNotBeCalled {
    async fn chat(&self, _messages: &[ChatMessage]) -> Result<ChatResponseWithModel, ScanError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Returning an empty array rather than panicking, so that if the guard is
        // bypassed the loop terminates on an empty batch instead of running
        // forever. The assertion below catches that this was reached at all.
        Ok(ChatResponseWithModel {
            content: "[]".to_string(),
            model_used: "test".to_string(),
        })
    }
}

fn findings(n: usize) -> Vec<VulnerabilityFinding> {
    (0..n)
        .map(|i| VulnerabilityFinding {
            title: format!("finding {i}"),
            file_path: format!("src/f{i}.php"),
            code_snippet: Some("echo 1;".to_string()),
            ..Default::default()
        })
        .collect()
}

async fn run(batch_size: usize) -> (Vec<(VerificationStatus, String)>, u64, usize) {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let client = MustNotBeCalled {
        calls: std::sync::Arc::clone(&calls),
    };
    let prompts: HashMap<String, String> = HashMap::new();
    let primitives: HashMap<String, Vec<String>> = HashMap::new();
    let (results, fallback) =
        verify_findings_batched(&client, &findings(3), batch_size, &prompts, &primitives).await;
    let seen = calls.load(std::sync::atomic::Ordering::Relaxed);
    (results, fallback, seen)
}

/// A batch size of zero must short-circuit, not fall through into the loop.
#[tokio::test]
async fn a_zero_batch_size_short_circuits() {
    let (results, fallback, seen) = run(0).await;

    assert_eq!(
        seen, 0,
        "batch_size 0 reached the model: the guard at the top of \
         verify_findings_batched did not short-circuit"
    );
    assert!(
        results.is_empty(),
        "batch_size 0 must return no verdicts, got {results:?}"
    );
    assert_eq!(fallback, 0);
}

/// One is the other side of the same guard. Both must skip the loop.
#[tokio::test]
async fn a_batch_size_of_one_short_circuits() {
    let (_results, _fallback, seen) = run(1).await;
    assert_eq!(
        seen, 0,
        "batch_size 1 reached the model: the `batch_size <= 1` guard did not hold"
    );
}
