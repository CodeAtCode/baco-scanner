//! Unit tests for src/context/triple_path.rs - TriplePathContext

use baco::context::triple_path::TriplePathContext;
use baco::context::Language;
use baco::retrieval::CweKnowledgeBase;

// ============================================================================
// TriplePathContext tests
// ============================================================================

#[test]
fn test_triple_path_build_empty() {
    // Use more meaningful code that won't be filtered out
    let ctx = TriplePathContext::build(
        "strcpy(dest, src);",
        Language::C,
        &CweKnowledgeBase::load_embedded().unwrap(),
        10,
    )
    .unwrap();
    let section = ctx.to_prompt_section();
    assert!(section.contains("%%TRIPLE_PATH_CONTEXT%%"));
}

#[test]
fn test_triple_path_with_semantic() {
    let ctx = TriplePathContext::build(
        "strcpy(dest, src);",
        Language::C,
        &CweKnowledgeBase::load_embedded().unwrap(),
        10,
    )
    .unwrap()
    .with_semantic("summary text".to_string());
    let section = ctx.to_prompt_section();
    assert!(section.contains("%%TRIPLE_PATH_CONTEXT%%"));
    assert!(section.contains("summary text"));
}

#[test]
fn test_triple_path_to_prompt_section_format() {
    let ctx = TriplePathContext::build(
        "strcpy(dest, src);",
        Language::C,
        &CweKnowledgeBase::load_embedded().unwrap(),
        10,
    )
    .unwrap();
    let section = ctx.to_prompt_section();

    assert!(section.contains("%%TRIPLE_PATH_CONTEXT%%"));
    assert!(section.contains("Control Path"));
    assert!(section.contains("Knowledge Path"));
}
