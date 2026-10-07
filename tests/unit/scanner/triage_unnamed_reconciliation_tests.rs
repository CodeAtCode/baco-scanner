//! A submitted file the triage reply never names must not vanish.
//!
//! `run_triage_cascade` looped over the MODEL's findings, so a file that was
//! submitted and absent from the reply landed in neither `files_to_analyze` nor
//! `skipped_files`: never analysed, never reported skipped. The fallback only
//! covered a malformed reply — but a well-formed one that simply omits a file
//! is not a failure, and was being read as a verdict.
//!
//! That is what produced scans reporting `6 indexed, 0 analyzed`.

use baco::error::ScanError;
use baco::indexer::FileInfo;
use baco::llm::{ChatMessage, ChatResponseWithModel, LlmChatClient};
use baco::scanner::phases::llm_phases::static_analysis::next_batch_end;
use baco::scanner::phases::llm_phases::static_analysis::run_triage_cascade;
use std::sync::{Arc, Mutex};

/// Returns a scripted reply per call, and records what it was asked.
struct ScriptedTriage {
    reply: String,
    asked: Arc<Mutex<Vec<String>>>,
}

impl LlmChatClient for ScriptedTriage {
    async fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponseWithModel, ScanError> {
        let user = messages
            .iter()
            .filter(|m| m.role == "user")
            .map(|m| m.content.clone())
            .collect::<Vec<_>>()
            .join("\n");
        self.asked.lock().expect("lock").push(user);

        Ok(ChatResponseWithModel {
            content: self.reply.clone(),
            model_used: "scripted".to_string(),
        })
    }
}

/// Real files on disk, because triage reads their contents before scoring.
fn submitted(dir: &std::path::Path, names: &[&str]) -> Vec<FileInfo> {
    names
        .iter()
        .map(|name| {
            let path = dir.join(name);
            std::fs::write(
                &path,
                format!(
                    "<?php\nfunction f_{}() {{ return 1; }}\n",
                    name.replace('.', "_")
                ),
            )
            .expect("write");
            FileInfo {
                size: 32,
                language: "php".to_string(),
                hash: None,
                path,
            }
        })
        .collect()
}

fn finding_json(paths: &[&std::path::Path], suspicion: f32) -> String {
    let items: Vec<String> = paths
        .iter()
        .map(|p| {
            format!(
                r#"{{"file": "{}", "summary_one_line": "x", "suspicion": {suspicion}, "reason": "r"}}"#,
                p.to_string_lossy()
            )
        })
        .collect();
    format!(r#"{{"findings": [{}]}}"#, items.join(","))
}

fn names_of(files: &[&FileInfo]) -> Vec<String> {
    let mut v: Vec<String> = files
        .iter()
        .map(|f| f.path.to_string_lossy().to_string())
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn test_a_file_the_reply_omits_is_still_analysed() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let files = submitted(dir.path(), &["a.php", "b.php", "c.php"]);

    // The model names only a and c. b was submitted and simply not mentioned.
    let reply = finding_json(&[&files[0].path, &files[2].path], 0.9);
    let client = ScriptedTriage {
        reply,
        asked: Arc::new(Mutex::new(Vec::new())),
    };

    let (to_analyze, skipped) = run_triage_cascade(&client, &files, &[], 10, 0.5).await;

    let analysed = names_of(&to_analyze);
    let b = files[1].path.to_string_lossy().to_string();
    assert!(
        analysed.contains(&b),
        "the omitted file must still be analysed; analysed {analysed:?}, skipped {skipped:?}"
    );
    assert_eq!(
        analysed.len(),
        3,
        "all three submitted files, got {analysed:?}"
    );
}

#[tokio::test]
async fn test_an_empty_findings_array_analyses_everything() {
    // The exact production failure: a valid reply that names nothing.
    let dir = tempfile::tempdir().expect("tmpdir");
    let files = submitted(dir.path(), &["a.php", "b.php", "c.php"]);

    let client = ScriptedTriage {
        reply: r#"{"findings": []}"#.to_string(),
        asked: Arc::new(Mutex::new(Vec::new())),
    };

    let (to_analyze, skipped) = run_triage_cascade(&client, &files, &[], 10, 0.5).await;

    assert_eq!(
        to_analyze.len(),
        3,
        "a valid reply naming nothing must not analyse nothing, got {:?}",
        names_of(&to_analyze)
    );
    assert!(skipped.is_empty(), "nothing was skipped, got {skipped:?}");
}

#[tokio::test]
async fn test_a_low_suspicion_file_is_still_skipped_not_reanalysed() {
    // The control. A file the model judged is skipped, and the reconciliation
    // must not undo a real verdict.
    let dir = tempfile::tempdir().expect("tmpdir");
    let files = submitted(dir.path(), &["a.php", "b.php"]);

    let reply = finding_json(&[&files[0].path, &files[1].path], 0.1);
    let client = ScriptedTriage {
        reply,
        asked: Arc::new(Mutex::new(Vec::new())),
    };

    let (to_analyze, skipped) = run_triage_cascade(&client, &files, &[], 10, 0.5).await;

    assert!(
        to_analyze.is_empty(),
        "both were judged uninteresting, got {:?}",
        names_of(&to_analyze)
    );
    assert_eq!(
        skipped.len(),
        2,
        "both must be reported skipped: {skipped:?}"
    );
}

#[tokio::test]
async fn test_a_named_file_is_not_added_twice() {
    // The regression guard on the reconciliation itself.
    let dir = tempfile::tempdir().expect("tmpdir");
    let files = submitted(dir.path(), &["a.php", "b.php"]);

    let reply = finding_json(&[&files[0].path, &files[1].path], 0.9);
    let client = ScriptedTriage {
        reply,
        asked: Arc::new(Mutex::new(Vec::new())),
    };

    let (to_analyze, skipped) = run_triage_cascade(&client, &files, &[], 10, 0.5).await;

    assert_eq!(
        names_of(&to_analyze).len(),
        2,
        "each file exactly once, got {:?}",
        names_of(&to_analyze)
    );
    assert!(skipped.is_empty(), "got {skipped:?}");
}

#[tokio::test]
async fn test_a_skipped_file_named_by_the_reply_is_not_readded() {
    // One named and skipped, one omitted. The omitted one is analysed; the
    // skipped one keeps its verdict and must not come back.
    let dir = tempfile::tempdir().expect("tmpdir");
    let files = submitted(dir.path(), &["a.php", "b.php"]);

    let reply = finding_json(&[&files[0].path], 0.1);
    let client = ScriptedTriage {
        reply,
        asked: Arc::new(Mutex::new(Vec::new())),
    };

    let (to_analyze, skipped) = run_triage_cascade(&client, &files, &[], 10, 0.5).await;

    let analysed = names_of(&to_analyze);
    let a = files[0].path.to_string_lossy().to_string();
    let b = files[1].path.to_string_lossy().to_string();
    assert!(!analysed.contains(&a), "a was skipped, got {analysed:?}");
    assert!(analysed.contains(&b), "b was omitted, got {analysed:?}");
    assert_eq!(skipped, vec![a], "got {skipped:?}");
}

#[tokio::test]
async fn test_reconciliation_spans_every_batch() {
    // The reconciliation is per batch. A reply that names nothing in a
    // multi-batch run must not lose the later batches either.
    let dir = tempfile::tempdir().expect("tmpdir");
    let files = submitted(dir.path(), &["a.php", "b.php", "c.php", "d.php"]);

    let client = ScriptedTriage {
        reply: r#"{"findings": []}"#.to_string(),
        asked: Arc::new(Mutex::new(Vec::new())),
    };

    let (to_analyze, _) = run_triage_cascade(&client, &files, &[], 2, 0.5).await;

    assert_eq!(
        to_analyze.len(),
        4,
        "all four across two batches, got {:?}",
        names_of(&to_analyze)
    );
}

#[tokio::test]
async fn test_an_already_analysed_file_is_not_resubmitted_or_reanalysed() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let files = submitted(dir.path(), &["a.php", "b.php"]);
    let already = vec![files[0].path.to_string_lossy().to_string()];

    let asked = Arc::new(Mutex::new(Vec::new()));
    let client = ScriptedTriage {
        reply: r#"{"findings": []}"#.to_string(),
        asked: Arc::clone(&asked),
    };

    let (to_analyze, _) = run_triage_cascade(&client, &files, &already, 10, 0.5).await;

    assert_eq!(
        names_of(&to_analyze),
        vec![files[1].path.to_string_lossy().to_string()],
        "the already-analysed file must not come back"
    );
    let prompts = asked.lock().expect("lock").clone();
    assert!(
        !prompts.iter().any(|p| p.contains("a.php")),
        "the already-analysed file must not be submitted at all: {prompts:?}"
    );
}

#[tokio::test]
async fn test_a_malformed_reply_still_falls_back_to_everything() {
    // The pre-existing fallback must keep working alongside the new pass.
    let dir = tempfile::tempdir().expect("tmpdir");
    let files = submitted(dir.path(), &["a.php", "b.php"]);

    let client = ScriptedTriage {
        reply: "{ not json".to_string(),
        asked: Arc::new(Mutex::new(Vec::new())),
    };

    let (to_analyze, _) = run_triage_cascade(&client, &files, &[], 10, 0.5).await;

    assert_eq!(to_analyze.len(), 2, "got {:?}", names_of(&to_analyze));
}
/// A batch size of zero must still advance the cursor.
///
/// `end = start + batch_size` with a batch size of zero leaves the cursor pinned,
/// and the sweep then runs forever without ever yielding. `triage.batch_size` is
/// user-configurable and nothing rejected zero.
///
/// This asserts the arithmetic rather than running the sweep. A `while` that never
/// yields cannot be interrupted by `tokio::time::timeout`, so a test that ran the
/// loop to observe the hang would take the whole binary down instead of failing —
/// which is why a mutation run reported this as a 600s timeout rather than a caught
/// mutant.
#[test]
fn a_zero_batch_size_still_advances_the_cursor() {
    // The cursor must strictly increase or the loop never terminates.
    assert_eq!(
        next_batch_end(10, 0, 0),
        Some(1),
        "a batch size of zero must degrade to one file per request, not to no progress"
    );
    assert_eq!(
        next_batch_end(10, 5, 0),
        Some(6),
        "a zero batch size must keep advancing from any cursor"
    );

    // Normal sizes still batch.
    assert_eq!(next_batch_end(10, 0, 4), Some(4));
    assert_eq!(
        next_batch_end(10, 8, 4),
        Some(10),
        "the last batch is clipped"
    );

    // And a batch larger than the remainder does not overshoot.
    assert_eq!(next_batch_end(3, 2, 8), Some(3));
}

/// Whatever the batch size, a sweep must reach the end and stop.
#[test]
fn a_sweep_reaches_the_end_for_every_batch_size() {
    for batch_size in [0u8, 1, 3, 8, 200] {
        let total = 17usize;
        let mut cursor = 0usize;
        let mut steps = 0usize;
        while let Some(end) = next_batch_end(total, cursor, batch_size) {
            assert!(
                end > cursor,
                "batch_size {batch_size} left the cursor at {cursor}, so the sweep never ends"
            );
            cursor = end;
            steps += 1;
            assert!(
                steps <= total,
                "batch_size {batch_size} made no progress per file"
            );
        }
        assert_eq!(cursor, total, "batch_size {batch_size} stopped short");
    }
}
