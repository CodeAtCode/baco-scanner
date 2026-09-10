//! Tests for chunked analysis of oversized files in `llm_analysis`.
//!
//! Oversized files must be split into line-exact tree-sitter slices (each
//! within the byte cap) instead of being skipped, so LLM-reported line
//! numbers can be mapped back to absolute file lines.

use baco::llm_analysis::LlmAnalyzer;

/// PHP fixture: `count` padded top-level functions.
fn php_functions(count: usize, pad_lines: usize) -> String {
    let mut out = String::from("<?php\n\n");
    for i in 0..count {
        out.push_str(&format!("function func_{i}() {{\n"));
        for j in 0..pad_lines {
            out.push_str(&format!("    $v_{i}_{j} = 'pad line value {j}';\n"));
        }
        out.push_str("}\n\n");
    }
    out
}

fn assert_exact_slice(content: &str, chunk: &baco::llm_analysis::ChunkRange) {
    let lines: Vec<&str> = content.lines().collect();
    let expected = lines[chunk.start_line - 1..chunk.end_line].join("\n");
    // Hard-split parts carry the trailing newline of their last line.
    let text = chunk.text.trim_end_matches('\n');
    assert_eq!(
        text, expected,
        "chunk {}-{} is not an exact file slice",
        chunk.start_line, chunk.end_line
    );
}

fn assert_ordered_disjoint(chunks: &[baco::llm_analysis::ChunkRange]) {
    for pair in chunks.windows(2) {
        assert!(
            pair[1].start_line > pair[0].start_line,
            "chunks must be ordered by start line"
        );
    }
}

#[test]
fn chunks_are_exact_file_slices_within_cap() {
    let content = php_functions(4, 3);
    let chunks = LlmAnalyzer::chunk_file_with_ranges(&content, "php", 400);

    assert!(
        !chunks.is_empty(),
        "php functions should produce at least one chunk"
    );
    assert_ordered_disjoint(&chunks);
    for chunk in &chunks {
        assert_exact_slice(&content, chunk);
        assert!(
            chunk.text.len() <= 400,
            "chunk of {} bytes exceeds the 400-byte cap",
            chunk.text.len()
        );
    }
}

#[test]
fn chunks_cover_every_function_line() {
    let content = php_functions(5, 4);
    let chunks = LlmAnalyzer::chunk_file_with_ranges(&content, "php", 600);

    for (idx, line_text) in content.lines().enumerate() {
        let line_no = idx + 1;
        if line_text.contains("function func_") {
            assert!(
                chunks
                    .iter()
                    .any(|c| line_no >= c.start_line && line_no <= c.end_line),
                "function line {line_no} must be covered by a chunk"
            );
        }
    }
}

#[test]
fn oversized_function_hard_splits_at_line_boundaries() {
    let mut content = String::from("<?php\n\nfunction giant() {\n");
    for i in 0..40 {
        content.push_str(&format!(
            "    $line_{i} = 'some reasonably long padding line number {i}';\n"
        ));
    }
    content.push_str("}\n");

    let max_bytes = 300;
    let chunks = LlmAnalyzer::chunk_file_with_ranges(&content, "php", max_bytes);

    assert!(
        chunks.len() >= 2,
        "a giant function must be split, got {} chunk(s)",
        chunks.len()
    );
    for pair in chunks.windows(2) {
        assert_eq!(
            pair[0].end_line + 1,
            pair[1].start_line,
            "hard-split parts must be contiguous"
        );
    }
    for chunk in &chunks {
        assert!(
            chunk.text.len() <= max_bytes,
            "part of {} bytes exceeds the {max_bytes}-byte cap",
            chunk.text.len()
        );
        assert_exact_slice(&content, chunk);
    }
}

#[test]
fn oversized_class_splits_into_method_level_slices() {
    let mut content = String::from("<?php\n\nclass Big {\n");
    for m in 0..6 {
        content.push_str(&format!("    public function method_{m}() {{\n"));
        for i in 0..6 {
            content.push_str(&format!(
                "        $x = 'method {m} padding value number {i}';\n"
            ));
        }
        content.push_str("    }\n\n");
    }
    content.push_str("}\n");

    let chunks = LlmAnalyzer::chunk_file_with_ranges(&content, "php", 400);

    assert!(
        chunks.len() >= 2,
        "a huge class should yield multiple method-level chunks, got {}",
        chunks.len()
    );
    for chunk in &chunks {
        assert!(
            chunk.text.len() <= 400,
            "chunk of {} bytes exceeds the 400-byte cap",
            chunk.text.len()
        );
        assert_exact_slice(&content, chunk);
    }
    for (idx, line_text) in content.lines().enumerate() {
        let line_no = idx + 1;
        if line_text.contains("padding value number") {
            assert!(
                chunks
                    .iter()
                    .any(|c| line_no >= c.start_line && line_no <= c.end_line),
                "method body line {line_no} must be covered by a chunk"
            );
        }
    }
}

#[test]
fn unsupported_language_yields_no_chunks() {
    let content = php_functions(2, 2);
    assert!(
        LlmAnalyzer::chunk_file_with_ranges(&content, "go", 400).is_empty(),
        "languages without a bundled tree-sitter parser must yield no chunks"
    );
}

#[test]
fn language_for_extension_maps_bundled_chunkers() {
    assert_eq!(LlmAnalyzer::language_for_extension("php"), Some("php"));
    assert_eq!(LlmAnalyzer::language_for_extension("phtml"), Some("php"));
    assert_eq!(LlmAnalyzer::language_for_extension("rs"), Some("rust"));
    assert_eq!(
        LlmAnalyzer::language_for_extension("tsx"),
        Some("typescript")
    );
    assert_eq!(LlmAnalyzer::language_for_extension("go"), None);
}

#[test]
fn map_chunk_line_treats_in_range_as_absolute() {
    assert_eq!(baco::llm_analysis::map_chunk_line(150, 100, 200), 150);
    assert_eq!(baco::llm_analysis::map_chunk_line(100, 100, 200), 100);
    assert_eq!(baco::llm_analysis::map_chunk_line(200, 100, 200), 200);
}

#[test]
fn map_chunk_line_offsets_relative_reports() {
    assert_eq!(baco::llm_analysis::map_chunk_line(1, 100, 200), 100);
    assert_eq!(baco::llm_analysis::map_chunk_line(50, 100, 200), 149);
}

#[test]
fn map_chunk_line_clamps_out_of_range() {
    assert_eq!(baco::llm_analysis::map_chunk_line(500, 100, 200), 100);
    assert_eq!(baco::llm_analysis::map_chunk_line(0, 100, 200), 100);
}
