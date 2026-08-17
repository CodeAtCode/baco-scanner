//! Unit tests for src/context/pacvd_extractor.rs - PacVD primitive-API abstraction

use baco::context::pacvd_extractor::{
    extract, auto_level, AbstractionLevel, categorize, tag_cwe,
};

use baco::context::callee_walker::{extract_call_sites, CallSite};
use std::collections::BTreeSet;

// ============================================================================
// AbstractionLevel tests
// ============================================================================

#[test]
fn test_abstraction_level_ordering() {
    assert!(AbstractionLevel::Primitive < AbstractionLevel::Typed);
    assert!(AbstractionLevel::Typed < AbstractionLevel::Grouped);
    assert!(AbstractionLevel::Grouped < AbstractionLevel::Semantic);
}

#[test]
fn test_abstraction_level_equality() {
    assert_eq!(AbstractionLevel::Primitive, AbstractionLevel::Primitive);
    assert_ne!(AbstractionLevel::Primitive, AbstractionLevel::Typed);
}

#[test]
fn test_abstraction_level_debug() {
    assert_eq!(format!("{:?}", AbstractionLevel::Primitive), "Primitive");
    assert_eq!(format!("{:?}", AbstractionLevel::Typed), "Typed");
    assert_eq!(format!("{:?}", AbstractionLevel::Grouped), "Grouped");
    assert_eq!(format!("{:?}", AbstractionLevel::Semantic), "Semantic");
}

#[test]
fn test_abstraction_level_clone() {
    let level = AbstractionLevel::Grouped;
    let level_clone = level;
    assert_eq!(level, level_clone);
}

#[test]
fn test_abstraction_level_copy() {
    let level = AbstractionLevel::Semantic;
    let level_copy = level; // Copy, not move
    assert_eq!(level, level_copy);
}

// ============================================================================
// auto_level tests
// ============================================================================

#[test]
fn test_auto_level_very_small() {
    assert_eq!(auto_level(1024), AbstractionLevel::Primitive);
}

#[test]
fn test_auto_level_small() {
    assert_eq!(auto_level(4096), AbstractionLevel::Primitive);
}

#[test]
fn test_auto_level_just_under_small_threshold() {
    assert_eq!(auto_level(4095), AbstractionLevel::Primitive);
}

#[test]
fn test_auto_level_medium() {
    assert_eq!(auto_level(8192), AbstractionLevel::Typed);
}

#[test]
fn test_auto_level_just_under_medium_threshold() {
    assert_eq!(auto_level(16383), AbstractionLevel::Typed);
}

#[test]
fn test_auto_level_large() {
    assert_eq!(auto_level(32768), AbstractionLevel::Grouped);
}

#[test]
fn test_auto_level_just_under_large_threshold() {
    assert_eq!(auto_level(65535), AbstractionLevel::Grouped);
}

#[test]
fn test_auto_level_xl() {
    assert_eq!(auto_level(128000), AbstractionLevel::Semantic);
}

#[test]
fn test_auto_level_very_large() {
    assert_eq!(auto_level(1000000), AbstractionLevel::Semantic);
}

#[test]
fn test_auto_level_zero() {
    assert_eq!(auto_level(0), AbstractionLevel::Primitive);
}

// ============================================================================
// extract tests - Primitive level
// ============================================================================

#[test]
fn test_extract_primitive_level() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "strcpy".to_string(), arg_count: 2 });
    sites.insert(CallSite { callee: "malloc".to_string(), arg_count: 1 });

    let vector = extract(&sites, AbstractionLevel::Primitive);

    assert_eq!(vector.level, AbstractionLevel::Primitive);
    assert_eq!(vector.primitive.len(), 2);
    assert!(vector.typed.is_empty());
    assert!(vector.grouped.is_empty());
    assert!(vector.semantic.is_empty());
}

#[test]
fn test_extract_primitive_format() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "foo".to_string(), arg_count: 3 });

    let vector = extract(&sites, AbstractionLevel::Primitive);

    assert!(vector.primitive.iter().any(|s| s.contains("foo")));
    assert!(vector.primitive.iter().any(|s| s.contains("3")));
}

// ============================================================================
// extract tests - Typed level
// ============================================================================

#[test]
fn test_extract_typed_level() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "foo".to_string(), arg_count: 1 });
    sites.insert(CallSite { callee: "bar".to_string(), arg_count: 2 });

    let vector = extract(&sites, AbstractionLevel::Typed);

    assert_eq!(vector.level, AbstractionLevel::Typed);
    assert!(!vector.typed.is_empty());
    assert!(vector.grouped.is_empty());
    assert!(vector.semantic.is_empty());
}

#[test]
fn test_extract_typed_contains_unknown() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "foo".to_string(), arg_count: 1 });

    let vector = extract(&sites, AbstractionLevel::Typed);

    assert!(vector.typed.contains_key("unknown"));
}

// ============================================================================
// extract tests - Grouped level
// ============================================================================

#[test]
fn test_extract_grouped_level() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "strcpy".to_string(), arg_count: 2 });
    sites.insert(CallSite { callee: "system".to_string(), arg_count: 1 });
    sites.insert(CallSite { callee: "printf".to_string(), arg_count: 1 });

    let vector = extract(&sites, AbstractionLevel::Grouped);

    assert_eq!(vector.level, AbstractionLevel::Grouped);
    assert!(!vector.grouped.is_empty());
    assert!(vector.semantic.is_empty());
}

#[test]
fn test_extract_grouped_memory_category() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "strcpy".to_string(), arg_count: 2 });
    sites.insert(CallSite { callee: "memcpy".to_string(), arg_count: 3 });
    sites.insert(CallSite { callee: "malloc".to_string(), arg_count: 1 });

    let vector = extract(&sites, AbstractionLevel::Grouped);

    assert!(vector.grouped.contains_key("memory"));
}

#[test]
fn test_extract_grouped_io_category() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "printf".to_string(), arg_count: 1 });
    sites.insert(CallSite { callee: "fopen".to_string(), arg_count: 2 });
    sites.insert(CallSite { callee: "read".to_string(), arg_count: 3 });

    let vector = extract(&sites, AbstractionLevel::Grouped);

    assert!(vector.grouped.contains_key("I/O"));
}

#[test]
fn test_extract_grouped_control_flow_category() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "system".to_string(), arg_count: 1 });
    sites.insert(CallSite { callee: "execve".to_string(), arg_count: 3 });

    let vector = extract(&sites, AbstractionLevel::Grouped);

    assert!(vector.grouped.contains_key("control_flow"));
}

#[test]
fn test_extract_grouped_crypto_category() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "aes_encrypt".to_string(), arg_count: 2 });
    sites.insert(CallSite { callee: "sha256_hash".to_string(), arg_count: 1 });

    let vector = extract(&sites, AbstractionLevel::Grouped);

    assert!(vector.grouped.contains_key("crypto"));
}

#[test]
fn test_extract_grouped_database_category() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "sql_query".to_string(), arg_count: 2 });
    sites.insert(CallSite { callee: "db_connect".to_string(), arg_count: 1 });

    let vector = extract(&sites, AbstractionLevel::Grouped);

    assert!(vector.grouped.contains_key("database"));
}

#[test]
fn test_extract_grouped_other_category() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "unknown_func".to_string(), arg_count: 1 });

    let vector = extract(&sites, AbstractionLevel::Grouped);

    assert!(vector.grouped.contains_key("other"));
}

// ============================================================================
// extract tests - Semantic level
// ============================================================================

#[test]
fn test_extract_semantic_level() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "strcpy".to_string(), arg_count: 2 });
    sites.insert(CallSite { callee: "system".to_string(), arg_count: 1 });

    let vector = extract(&sites, AbstractionLevel::Semantic);

    assert_eq!(vector.level, AbstractionLevel::Semantic);
    assert!(!vector.semantic.is_empty());
}

#[test]
fn test_extract_semantic_buffer_overflow() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "strcpy".to_string(), arg_count: 2 });

    let vector = extract(&sites, AbstractionLevel::Semantic);

    assert!(vector.semantic.iter().any(|(k, _)| k.contains("buffer_overflow")));
}

#[test]
fn test_extract_semantic_command_injection() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "system".to_string(), arg_count: 1 });

    let vector = extract(&sites, AbstractionLevel::Semantic);

    assert!(vector.semantic.iter().any(|(k, _)| k.contains("command_injection")));
}

#[test]
fn test_extract_semantic_double_free() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "free".to_string(), arg_count: 1 });

    let vector = extract(&sites, AbstractionLevel::Semantic);

    assert!(vector.semantic.iter().any(|(k, _)| k.contains("double_free")));
}

#[test]
fn test_extract_semantic_mem_mgmt() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "malloc".to_string(), arg_count: 1 });

    let vector = extract(&sites, AbstractionLevel::Semantic);

    assert!(vector.semantic.iter().any(|(k, _)| k.contains("mem_mgmt")));
}

#[test]
fn test_extract_semantic_off_by_one() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "strncpy".to_string(), arg_count: 3 });

    let vector = extract(&sites, AbstractionLevel::Semantic);

    assert!(vector.semantic.iter().any(|(k, _)| k.contains("off_by_one")));
}

#[test]
fn test_extract_semantic_unknown_funcs_not_tagged() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "unknown_func".to_string(), arg_count: 1 });

    let vector = extract(&sites, AbstractionLevel::Semantic);

    // Unknown functions should not appear in semantic tags
    assert!(vector.semantic.is_empty());
}

// ============================================================================
// to_prompt_section tests
// ============================================================================

#[test]
fn test_to_prompt_section_primitive() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "strcpy".to_string(), arg_count: 2 });

    let vector = extract(&sites, AbstractionLevel::Primitive);
    let section = vector.to_prompt_section();

    assert!(section.contains("%%PACVD_CONTEXT%%"));
    assert!(section.contains("(abstraction level: Primitive)"));
    assert!(section.contains("### Primitive API calls"));
    assert!(section.contains("strcpy"));
    assert!(!section.contains("### Typed grouping"));
    assert!(!section.contains("### Functional grouping"));
    assert!(!section.contains("### CWE-relevant tags"));
}

#[test]
fn test_to_prompt_section_typed() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "foo".to_string(), arg_count: 1 });

    let vector = extract(&sites, AbstractionLevel::Typed);
    let section = vector.to_prompt_section();

    assert!(section.contains("%%PACVD_CONTEXT%%"));
    assert!(section.contains("### Primitive API calls"));
    assert!(section.contains("### Typed grouping"));
    assert!(!section.contains("### Functional grouping"));
    assert!(!section.contains("### CWE-relevant tags"));
}

#[test]
fn test_to_prompt_section_grouped() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "strcpy".to_string(), arg_count: 2 });

    let vector = extract(&sites, AbstractionLevel::Grouped);
    let section = vector.to_prompt_section();

    assert!(section.contains("%%PACVD_CONTEXT%%"));
    assert!(section.contains("### Primitive API calls"));
    assert!(section.contains("### Typed grouping"));
    assert!(section.contains("### Functional grouping"));
    assert!(!section.contains("### CWE-relevant tags"));
}

#[test]
fn test_to_prompt_section_semantic() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite { callee: "strcpy".to_string(), arg_count: 2 });

    let vector = extract(&sites, AbstractionLevel::Semantic);
    let section = vector.to_prompt_section();

    assert!(section.contains("%%PACVD_CONTEXT%%"));
    assert!(section.contains("### Primitive API calls"));
    assert!(section.contains("### Typed grouping"));
    assert!(section.contains("### Functional grouping"));
    assert!(section.contains("### CWE-relevant tags"));
}

#[test]
fn test_to_prompt_section_empty() {
    let sites = BTreeSet::new();
    let vector = extract(&sites, AbstractionLevel::Primitive);
    let section = vector.to_prompt_section();

    assert!(section.contains("%%PACVD_CONTEXT%%"));
    assert!(section.contains("### Primitive API calls"));
}

// ============================================================================
// categorize function tests
// ============================================================================

#[test]
fn test_categorize_io_functions() {
    let io_funcs = ["fopen", "fclose", "fread", "fwrite", "open", "close", "read", "write",
                    "printf", "fprintf", "sprintf", "scanf", "fgets", "fputs", "puts"];
    
    for func in io_funcs {
            assert_eq!(categorize(func), "I/O");
    }
}

#[test]
fn test_categorize_memory_functions() {
    let mem_funcs = ["memcpy", "memset", "memmove", "strcpy", "strncpy", "strcat", "strncat",
                     "strlen", "strcmp", "strncmp", "malloc", "calloc", "realloc", "free", "alloca"];
    
    for func in mem_funcs {
        assert_eq!(categorize(func), "memory", "Function {} should be categorized as memory", func);
    }
}

#[test]
fn test_categorize_string_functions() {
    let str_funcs = ["strtok", "strstr", "strchr", "strrchr", "sscanf", "snprintf", "vsnprintf"];
    
    for func in str_funcs {
        assert_eq!(categorize(func), "string", "Function {} should be categorized as string", func);
    }
}

#[test]
fn test_categorize_control_flow_functions() {
    let cf_funcs = ["system", "execve", "execl", "execvp", "popen", "fork", "exec", "eval"];
    
    for func in cf_funcs {
        assert_eq!(categorize(func), "control_flow", "Function {} should be categorized as control_flow", func);
    }
}

#[test]
fn test_categorize_crypto_functions() {
    assert_eq!(categorize("aes_encrypt"), "crypto");
    assert_eq!(categorize("sha256_hash"), "crypto");
    assert_eq!(categorize("hmac_sign"), "crypto");
    assert_eq!(categorize("rsa_verify"), "crypto");
}

#[test]
fn test_categorize_database_functions() {
    assert_eq!(categorize("sql_query"), "database");
    assert_eq!(categorize("db_connect"), "database");
}

#[test]
fn test_categorize_unknown() {
    assert_eq!(categorize("unknown_func"), "other");
    assert_eq!(categorize("my_custom_function"), "other");
}

#[test]
fn test_categorize_case_insensitive() {
    assert_eq!(categorize("STRCPY"), "memory");
    assert_eq!(categorize("System"), "control_flow");
    assert_eq!(categorize("PRINTF"), "I/O");
}

// ============================================================================
// tag_cwe function tests
// ============================================================================

#[test]
fn test_tag_cwe_buffer_overflow_strcpy() {
    let result = tag_cwe("strcpy");
    assert!(result.is_some());
    let (tag, cwe) = result.unwrap();
    assert_eq!(tag, "buffer_overflow");
    assert_eq!(cwe, "CWE-120");
}

#[test]
fn test_tag_cwe_buffer_overflow_strcat() {
    let result = tag_cwe("strcat");
    assert!(result.is_some());
    assert_eq!(result.unwrap().1, "CWE-120");
}

#[test]
fn test_tag_cwe_buffer_overflow_gets() {
    let result = tag_cwe("gets");
    assert!(result.is_some());
    assert_eq!(result.unwrap().1, "CWE-120");
}

#[test]
fn test_tag_cwe_buffer_overflow_memcpy() {
    let result = tag_cwe("memcpy");
    assert!(result.is_some());
    assert_eq!(result.unwrap().1, "CWE-119");
}

#[test]
fn test_tag_cwe_command_injection_system() {
    let result = tag_cwe("system");
    assert!(result.is_some());
    assert_eq!(result.unwrap().1, "CWE-78");
}

#[test]
fn test_tag_cwe_command_injection_execve() {
    let result = tag_cwe("execve");
    assert!(result.is_some());
    assert_eq!(result.unwrap().1, "CWE-78");
}

#[test]
fn test_tag_cwe_mem_mgmt_malloc() {
    let result = tag_cwe("malloc");
    assert!(result.is_some());
    assert_eq!(result.unwrap().1, "CWE-416");
}

#[test]
fn test_tag_cwe_double_free() {
    let result = tag_cwe("free");
    assert!(result.is_some());
    assert_eq!(result.unwrap().1, "CWE-415");
}

#[test]
fn test_tag_cwe_off_by_one_strncpy() {
    let result = tag_cwe("strncpy");
    assert!(result.is_some());
    assert_eq!(result.unwrap().1, "CWE-193");
}

#[test]
fn test_tag_cwe_unknown_function() {
    let result = tag_cwe("unknown_func");
    assert!(result.is_none());
}

#[test]
fn test_tag_cwe_printf_not_tagged() {
    let result = tag_cwe("printf");
    assert!(result.is_none());
}

// ============================================================================
// Integration tests
// ============================================================================

#[test]
fn test_full_extraction_workflow() {
    let source = r#"
void vulnerable(char *input) {
    char buffer[100];
    strcpy(buffer, input);
    system(input);
    free(buffer);
}
"#;

    let sites = extract_call_sites(source);
    let vector = extract(&sites, AbstractionLevel::Semantic);

    assert_eq!(vector.level, AbstractionLevel::Semantic);
    assert!(!vector.primitive.is_empty());
    assert!(!vector.typed.is_empty());
    assert!(!vector.grouped.is_empty());
    assert!(!vector.semantic.is_empty());

    let section = vector.to_prompt_section();
    assert!(section.contains("strcpy"));
    assert!(section.contains("system"));
    assert!(section.contains("buffer_overflow"));
    assert!(section.contains("command_injection"));
}

#[test]
fn test_auto_level_selection_workflow() {
    let source = "strcpy(buffer, input);";
    let sites = extract_call_sites(source);

    // Test with different context sizes
    let level_small = auto_level(2048);
    let level_medium = auto_level(8192);
    let level_large = auto_level(32768);
    let level_xl = auto_level(128000);

    assert_eq!(level_small, AbstractionLevel::Primitive);
    assert_eq!(level_medium, AbstractionLevel::Typed);
    assert_eq!(level_large, AbstractionLevel::Grouped);
    assert_eq!(level_xl, AbstractionLevel::Semantic);

    // Extract at each level
    let v1 = extract(&sites, level_small);
    let v2 = extract(&sites, level_medium);
    let v3 = extract(&sites, level_large);
    let v4 = extract(&sites, level_xl);

    assert_eq!(v1.level, AbstractionLevel::Primitive);
    assert_eq!(v2.level, AbstractionLevel::Typed);
    assert_eq!(v3.level, AbstractionLevel::Grouped);
    assert_eq!(v4.level, AbstractionLevel::Semantic);
}