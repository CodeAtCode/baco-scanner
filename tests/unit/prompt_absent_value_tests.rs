//! What the judge is shown when a finding carries no source.
//!
//! A missing value substituted with "" or "0" does not read as absent. The judge
//! receives "Code Snippet:\n\n" and sees a file with empty content, which is
//! evidence about the code rather than a gap in what was collected. These tests
//! capture the prompt so the substitution, not the conclusion drawn from it, is
//! what gets asserted.

use baco::error::ScanError;
use baco::findings::VulnerabilityFinding;
use baco::llm::{ChatMessage, ChatResponseWithModel, LlmChatClient};
use std::sync::{Arc, Mutex};

/// Captures the prompt instead of answering it.
struct PromptCapture {
    prompt: Arc<Mutex<String>>,
}

impl LlmChatClient for PromptCapture {
    async fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponseWithModel, ScanError> {
        let rendered = messages
            .iter()
            .map(|m| m.content.clone())
            .collect::<Vec<_>>()
            .join("\n");
        *self.prompt.lock().expect("prompt lock") = rendered;

        Ok(ChatResponseWithModel {
            content: r#"{"is_sound": true, "issues": [], "confidence_adjustment": 0.0}"#
                .to_string(),
            model_used: "capture".to_string(),
        })
    }
}

fn finding_without_source() -> VulnerabilityFinding {
    VulnerabilityFinding {
        title: "CWE-352: Missing CSRF check on dismiss_pointers()".to_string(),
        file_path: "wp-admin/post.php".to_string(),
        code_snippet: None,
        line_number: None,
        cwe_id: None,
        description: "The endpoint accepts a POST with no referer check.".to_string(),
        ..Default::default()
    }
}

async fn captured_prompt(finding: &VulnerabilityFinding) -> String {
    let prompt = Arc::new(Mutex::new(String::new()));
    let client = PromptCapture {
        prompt: Arc::clone(&prompt),
    };
    baco::llm_verification::rationale_check(&client, finding)
        .await
        .expect("the mock answers, so the check succeeds");
    prompt.lock().expect("prompt lock").clone()
}

#[tokio::test]
async fn a_missing_snippet_is_stated_not_rendered_as_empty_code() {
    let prompt = captured_prompt(&finding_without_source()).await;

    assert!(
        !prompt.contains("Code Snippet:\n\n"),
        "an empty snippet slot reads to the judge as source that was empty:\n{prompt}"
    );
    assert!(
        prompt.contains("no source snippet was captured"),
        "the prompt must say the source was not captured:\n{prompt}"
    );
}

#[tokio::test]
async fn a_missing_line_number_does_not_become_line_zero() {
    let prompt = captured_prompt(&finding_without_source()).await;

    assert!(
        !prompt.contains("wp-admin/post.php:0"),
        "\"file:0\" is a real line number, not an absent one:\n{prompt}"
    );
    assert!(
        prompt.contains("not recorded"),
        "the prompt must say the line was not recorded:\n{prompt}"
    );
}

#[tokio::test]
async fn a_missing_cwe_does_not_become_an_empty_label() {
    let prompt = captured_prompt(&finding_without_source()).await;

    assert!(
        !prompt.contains("CWE: \n"),
        "an empty CWE label reads as a classification with no value:\n{prompt}"
    );
}

#[tokio::test]
async fn a_present_snippet_is_passed_through_unchanged() {
    let mut finding = finding_without_source();
    finding.code_snippet = Some("check_ajax_referer(wp_unslash($_POST['action']));".to_string());
    finding.line_number = Some(42);
    finding.cwe_id = Some("CWE-352".to_string());

    let prompt = captured_prompt(&finding).await;

    assert!(
        prompt.contains("check_ajax_referer(wp_unslash($_POST['action']));"),
        "real code must reach the judge intact:\n{prompt}"
    );
    assert!(
        prompt.contains("wp-admin/post.php:42") && prompt.contains("CWE-352"),
        "real values must reach the judge intact:\n{prompt}"
    );
    assert!(
        !prompt.contains("no source snippet was captured"),
        "the absence notice must not appear when the source is present:\n{prompt}"
    );
}
