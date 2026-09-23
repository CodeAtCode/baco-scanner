//! Unit tests for uncovered pure branches in `llm_analysis.rs`.
//!
//! These tests cover cheap, pure code paths that don't require mockito:
//! - Oversized file early return in `analyze_file`
//! - Chunking logic in `parse_and_chunk` and `chunk_file_with_ranges`
//! - Line number handling in `chunk_from_span` and `slice_chunk`
//! - JSON parsing edge cases in `parse_llm_response`

use baco::llm::LlmConfig;
use baco::llm_analysis::LlmAnalyzer;
use tempfile::TempDir;

// ============================================================================
// Test fixtures
// ============================================================================

fn create_analyzer() -> LlmAnalyzer {
    let languages = vec!["rust".to_string()];
    let llm_config = LlmConfig {
        base_url: "http://test".to_string(),
        api_key: "test".to_string(),
        model: "test".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 1,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
        pricing: Default::default(),
    };

    let client = baco::llm::LlmClient::new(llm_config);
    LlmAnalyzer::new(
        client,
        languages,
        1024,
        &baco::config::ScannerConfig::default(),
    )
}

// ============================================================================
// Target 1: analyze_file oversized file early return (lines 532, 534–535, 537)
// ============================================================================

#[tokio::test]
async fn test_analyze_file_oversized_file_returns_empty() {
    let analyzer = create_analyzer();
    let temp_dir = TempDir::new().unwrap();

    // Create a file > 10 MB (MAX_CHUNK_READ_BYTES)
    let large_file = temp_dir.path().join("large.rs");
    let content = "fn main() {}\n".repeat(1_000_000); // ~15 MB
    std::fs::write(&large_file, &content).unwrap();

    let result = analyzer.analyze_file(&large_file).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

// ============================================================================
// Target 2: parse_and_chunk push current_chunk on oversized function (line 917)
// ============================================================================

#[test]
fn test_chunk_code_tree_sitter_oversized_function_pushes_current() {
    let analyzer = create_analyzer();

    // max_bytes=200, first function ~50 bytes, second function ~300 bytes
    // When second function is encountered, current_chunk has first function
    // and line 917 fires: push current_chunk before hard-splitting the oversized function
    let content = r#"fn small() {
    let x = 1;
}

fn huge_function() {
    // This function is intentionally large to exceed max_bytes
    let a = 1;
    let b = 2;
    let c = 3;
    let d = 4;
    let e = 5;
    let f = 6;
    let g = 7;
    let h = 8;
    let i = 9;
    let j = 10;
    let k = 11;
    let l = 12;
    let m = 13;
    let n = 14;
    let o = 15;
    let p = 16;
    let q = 17;
    let r = 18;
    let s = 19;
    let t = 20;
    let u = 21;
    let v = 22;
    let w = 23;
    let x = 24;
    let y = 25;
    let z = 26;
    let aa = 27;
    let bb = 28;
    let cc = 29;
    let dd = 30;
    let ee = 31;
    let ff = 32;
    let gg = 33;
    let hh = 34;
    let ii = 35;
    let jj = 36;
    let kk = 37;
    let ll = 38;
    let mm = 39;
    let nn = 40;
    let oo = 41;
    let pp = 42;
    let qq = 43;
    let rr = 44;
    let ss = 45;
    let tt = 46;
    let uu = 47;
    let vv = 48;
    let ww = 49;
    let xx = 50;
    let yy = 51;
    let zz = 52;
}
"#;

    let chunks = analyzer.chunk_code_tree_sitter(content, "rust", 200);

    // Should have at least 2 chunks: one for small function, one+ for huge function
    assert!(
        chunks.len() >= 2,
        "Expected at least 2 chunks, got {}",
        chunks.len()
    );

    // First chunk should contain the small function
    assert!(chunks[0].contains("fn small()"));

    // Subsequent chunks should contain parts of the huge function with the marker
    let mut found_marker = false;
    for chunk in &chunks[1..] {
        if chunk.contains("[chunk continues - function too large") {
            found_marker = true;
            break;
        }
    }
    assert!(
        found_marker,
        "Expected hard-split marker in oversized function chunks"
    );
}

// ============================================================================
// Target 3: parse_and_chunk start new chunk when function doesn't fit (lines 949–953)
// ============================================================================

#[test]
fn test_chunk_code_tree_sitter_start_new_chunk() {
    let analyzer = create_analyzer();

    // max_bytes=200, first function ~180 bytes, second function ~50 bytes
    // When second function doesn't fit in remaining space, lines 949-953 fire:
    // push current_chunk and start new one with preamble + second function
    let content = r#"// preamble comment
use std::collections::HashMap;

fn first_function() {
    let a = 1;
    let b = 2;
    let c = 3;
    let d = 4;
    let e = 5;
    let f = 6;
    let g = 7;
    let h = 8;
    let i = 9;
    let j = 10;
    let k = 11;
    let l = 12;
    let m = 13;
    let n = 14;
    let o = 15;
    let p = 16;
    let q = 17;
    let r = 18;
    let s = 19;
    let t = 20;
    let u = 21;
    let v = 22;
    let w = 23;
    let x = 24;
    let y = 25;
    let z = 26;
}

fn second_function() {
    let x = 42;
}
"#;

    let chunks = analyzer.chunk_code_tree_sitter(content, "rust", 200);

    // The first function is ~200+ bytes, so it gets hard-split
    // The second function ends up in a later chunk with the preamble
    assert!(
        chunks.len() >= 4,
        "Expected at least 4 chunks, got {}",
        chunks.len()
    );

    // First chunk should contain preamble and start of first function
    assert!(chunks[0].contains("// preamble comment"));
    assert!(chunks[0].contains("fn first_function()"));

    // Find the chunk containing second_function (should have preamble)
    let mut found_second_with_preamble = false;
    for chunk in &chunks {
        if chunk.contains("fn second_function()") {
            assert!(
                chunk.contains("// preamble comment"),
                "Chunk with second_function should contain preamble"
            );
            found_second_with_preamble = true;
            break;
        }
    }
    assert!(
        found_second_with_preamble,
        "Should find second_function with preamble"
    );
}

// ============================================================================
// Target 4: chunk_file_with_ranges oversized unit push (line 1062)
// ============================================================================

#[test]
fn test_chunk_file_with_ranges_oversized_unit_push() {
    // max_bytes=100, first function ~40 bytes, second function ~200 bytes
    // When second function exceeds max_bytes, line 1062 fires:
    // push current group chunk before hard-splitting the oversized unit
    let content = r#"fn small_one() {
    let x = 1;
}

fn giant_function() {
    // This function is intentionally large
    let a = 1;
    let b = 2;
    let c = 3;
    let d = 4;
    let e = 5;
    let f = 6;
    let g = 7;
    let h = 8;
    let i = 9;
    let j = 10;
    let k = 11;
    let l = 12;
    let m = 13;
    let n = 14;
    let o = 15;
    let p = 16;
    let q = 17;
    let r = 18;
    let s = 19;
    let t = 20;
    let u = 21;
    let v = 22;
    let w = 23;
    let x = 24;
    let y = 25;
    let z = 26;
    let aa = 27;
    let bb = 28;
    let cc = 29;
    let dd = 30;
    let ee = 31;
    let ff = 32;
    let gg = 33;
    let hh = 34;
    let ii = 35;
    let jj = 36;
    let kk = 37;
    let ll = 38;
    let mm = 39;
    let nn = 40;
    let oo = 41;
    let pp = 42;
    let qq = 43;
    let rr = 44;
    let ss = 45;
    let tt = 46;
    let uu = 47;
    let vv = 48;
    let ww = 49;
    let xx = 50;
    let yy = 51;
    let zz = 52;
}
"#;

    let chunks = LlmAnalyzer::chunk_file_with_ranges(content, "rust", 100);

    // Should have at least 2 chunks: one for small function, one+ for giant function
    assert!(
        chunks.len() >= 2,
        "Expected at least 2 chunks, got {}",
        chunks.len()
    );

    // First chunk should contain the small function
    assert!(chunks[0].text.contains("fn small_one()"));

    // Subsequent chunks should contain parts of the giant function
    let mut found_giant = false;
    for chunk in &chunks[1..] {
        if chunk.text.contains("fn giant_function()") {
            found_giant = true;
            break;
        }
    }
    assert!(found_giant, "Expected giant function in chunks");
}

// ============================================================================
// Target 5: chunk_from_span no trailing newline (line 1094)
// ============================================================================

#[test]
fn test_chunk_from_span_no_trailing_newline() {
    // Content whose span end does NOT end with '\n'
    let content = "fn a() {}\nfn b() {}"; // No trailing newline

    let chunks = LlmAnalyzer::chunk_file_with_ranges(content, "rust", 1000);

    assert!(!chunks.is_empty(), "Should produce at least one chunk");

    // Check that line numbers are calculated correctly without trailing newline
    for chunk in &chunks {
        // Verify the chunk text matches the expected lines
        let lines: Vec<&str> = content.lines().collect();
        let expected_text = lines[chunk.start_line - 1..chunk.end_line].join("\n");

        assert_eq!(
            chunk.text.trim_end_matches('\n'),
            expected_text,
            "Chunk {}-{} should be exact slice (no trailing newline case)",
            chunk.start_line,
            chunk.end_line
        );
    }
}

// ============================================================================
// Target 6: slice_chunk no trailing newline (line 1168)
// ============================================================================

#[test]
fn test_slice_chunk_no_trailing_newline() {
    // Single large function (no trailing newline) exceeding max_bytes
    let mut content = String::from("fn huge() {\n");
    for i in 0..50 {
        content.push_str(&format!("    let x{} = {};\n", i, i));
    }
    content.push('}'); // No trailing newline

    let max_bytes = 50;
    let chunks = LlmAnalyzer::chunk_file_with_ranges(&content, "rust", max_bytes);

    assert!(
        chunks.len() >= 2,
        "Oversized function should be split, got {} chunks",
        chunks.len()
    );

    // Verify each chunk is within the byte cap
    for chunk in &chunks {
        assert!(
            chunk.text.len() <= max_bytes,
            "Chunk of {} bytes exceeds the {}-byte cap",
            chunk.text.len(),
            max_bytes
        );
    }

    // Verify line numbers are correct
    let lines: Vec<&str> = content.lines().collect();
    for chunk in &chunks {
        let expected_text = lines[chunk.start_line - 1..chunk.end_line].join("\n");

        assert_eq!(
            chunk.text.trim_end_matches('\n'),
            expected_text,
            "Chunk {}-{} should be exact slice (hard-split no trailing newline)",
            chunk.start_line,
            chunk.end_line
        );
    }
}

// ============================================================================
// Target 7: parse_llm_response missing line field (line 1339)
// ============================================================================

#[test]
fn test_parse_llm_response_missing_line_defaults_to_one() {
    let analyzer = create_analyzer();

    // JSON array with a finding that omits the "line" field
    let json = r#"[{"severity":"high","title":"Test","description":"d","cwe_id":"CWE-79","exploit_scenario":"Test","attack_complexity":"low","impact":"High","fix_code":"Fix","diff_hunk":"@@ -1,5 +1,7 @@", "recommendation":"Validate"}]"#;

    let result = analyzer.parse_llm_response(json, "test.rs", "test-model");

    assert!(result.is_ok(), "Should parse successfully");
    let findings = result.unwrap();

    assert_eq!(findings.len(), 1, "Should produce one finding");
    assert_eq!(
        findings[0].line_number,
        Some(1),
        "Line should default to 1 when missing"
    );
    assert_eq!(findings[0].title, "Test");
    assert_eq!(findings[0].severity, baco::findings::Severity::High);
}

// ============================================================================
// Additional edge case tests for chunking
// ============================================================================

#[test]
fn test_chunk_file_with_ranges_empty_content() {
    let chunks = LlmAnalyzer::chunk_file_with_ranges("", "rust", 100);
    assert!(chunks.is_empty(), "Empty content should yield no chunks");
}

#[test]
fn test_chunk_file_with_ranges_unsupported_language() {
    let content = "fn test() {}";
    let chunks = LlmAnalyzer::chunk_file_with_ranges(content, "go", 100);
    assert!(
        chunks.is_empty(),
        "Unsupported language should yield no chunks"
    );
}

#[test]
fn test_chunk_code_tree_sitter_empty_content() {
    let analyzer = create_analyzer();
    let chunks = analyzer.chunk_code_tree_sitter("", "rust", 100);
    assert_eq!(
        chunks.len(),
        1,
        "Empty content should fallback to truncate_code"
    );
}

#[test]
fn test_chunk_code_tree_sitter_unsupported_language() {
    let analyzer = create_analyzer();
    let chunks = analyzer.chunk_code_tree_sitter("fn test() {}", "go", 100);
    // Unsupported language returns empty from parse_and_chunk, but
    // chunk_code_tree_sitter falls back to truncate_code, so we get 1 chunk
    assert_eq!(
        chunks.len(),
        1,
        "Unsupported language should fallback to truncate_code"
    );
}
