//! Comprehensive unit tests for context extraction submodules.
//!
//! Tests:
//! - pacvd_extractor: AbstractionLevel, AbstractionVector, extract(), auto_level()
//! - callee_walker: CallSite, extract_call_sites()
//! - primitive_api: PRIMITIVE_API_TABLE, lookup(), PrimitiveApiVulnType

use baco::context::callee_walker::{extract_call_sites, CallSite};
use baco::context::pacvd_extractor::{auto_level, extract, AbstractionLevel};
use baco::context::primitive_api::{lookup, PrimitiveApiVulnType, PRIMITIVE_API_TABLE};
use std::collections::BTreeSet;

// ============================================================================
// AbstractionLevel tests
// ============================================================================

#[test]
fn test_abstraction_level_ordering() {
    assert!(AbstractionLevel::Primitive < AbstractionLevel::Typed);
    assert!(AbstractionLevel::Typed < AbstractionLevel::Grouped);
    assert!(AbstractionLevel::Grouped < AbstractionLevel::Semantic);
    assert!(AbstractionLevel::Primitive < AbstractionLevel::Grouped);
    assert!(AbstractionLevel::Primitive < AbstractionLevel::Semantic);
    assert!(AbstractionLevel::Typed < AbstractionLevel::Semantic);
}

#[test]
fn test_abstraction_level_equality() {
    assert_eq!(AbstractionLevel::Primitive, AbstractionLevel::Primitive);
    assert_eq!(AbstractionLevel::Typed, AbstractionLevel::Typed);
    assert_eq!(AbstractionLevel::Grouped, AbstractionLevel::Grouped);
    assert_eq!(AbstractionLevel::Semantic, AbstractionLevel::Semantic);
}

#[test]
fn test_abstraction_level_ord_values() {
    assert_eq!(AbstractionLevel::Primitive as u8, 0);
    assert_eq!(AbstractionLevel::Typed as u8, 1);
    assert_eq!(AbstractionLevel::Grouped as u8, 2);
    assert_eq!(AbstractionLevel::Semantic as u8, 3);
}

// ============================================================================
// auto_level tests
// ============================================================================

#[test]
fn test_auto_level_very_small_budget() {
    let level = auto_level(100);
    assert_eq!(level, AbstractionLevel::Primitive);
}

#[test]
fn test_auto_level_small_budget() {
    let level = auto_level(4096);
    assert_eq!(level, AbstractionLevel::Primitive);
}

#[test]
fn test_auto_level_boundary_primitive_to_typed() {
    assert_eq!(auto_level(4096), AbstractionLevel::Primitive);
    assert_eq!(auto_level(4097), AbstractionLevel::Typed);
}

#[test]
fn test_auto_level_medium_budget() {
    let level = auto_level(8192);
    assert_eq!(level, AbstractionLevel::Typed);
}

#[test]
fn test_auto_level_boundary_typed_to_grouped() {
    assert_eq!(auto_level(16384), AbstractionLevel::Typed);
    assert_eq!(auto_level(16385), AbstractionLevel::Grouped);
}

#[test]
fn test_auto_level_large_budget() {
    let level = auto_level(32768);
    assert_eq!(level, AbstractionLevel::Grouped);
}

#[test]
fn test_auto_level_boundary_grouped_to_semantic() {
    assert_eq!(auto_level(65536), AbstractionLevel::Grouped);
    assert_eq!(auto_level(65537), AbstractionLevel::Semantic);
}

#[test]
fn test_auto_level_very_large_budget() {
    let level = auto_level(128000);
    assert_eq!(level, AbstractionLevel::Semantic);
}

#[test]
fn test_auto_level_zero_budget() {
    let level = auto_level(0);
    assert_eq!(level, AbstractionLevel::Primitive);
}

// ============================================================================
// extract() tests
// ============================================================================

#[test]
fn test_extract_empty_sites() {
    let sites: BTreeSet<CallSite> = BTreeSet::new();
    let v = extract(&sites, AbstractionLevel::Primitive);
    assert_eq!(v.level, AbstractionLevel::Primitive);
    assert!(v.primitive.is_empty());
    assert!(v.typed.is_empty());
    assert!(v.grouped.is_empty());
    assert!(v.semantic.is_empty());
}

#[test]
fn test_extract_single_site_primitive() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite {
        callee: "printf".to_string(),
        arg_count: 1,
    });
    let v = extract(&sites, AbstractionLevel::Primitive);
    assert_eq!(v.primitive.len(), 1);
    assert!(v.primitive[0].contains("printf"));
    assert!(v.primitive[0].contains("1 arg"));
}

#[test]
fn test_extract_multiple_sites_primitive() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite {
        callee: "strcpy".to_string(),
        arg_count: 2,
    });
    sites.insert(CallSite {
        callee: "system".to_string(),
        arg_count: 1,
    });
    sites.insert(CallSite {
        callee: "malloc".to_string(),
        arg_count: 1,
    });
    let v = extract(&sites, AbstractionLevel::Primitive);
    assert_eq!(v.primitive.len(), 3);
    assert!(v.typed.is_empty());
    assert!(v.grouped.is_empty());
    assert!(v.semantic.is_empty());
}

#[test]
fn test_extract_typed_level() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite {
        callee: "strcpy".to_string(),
        arg_count: 2,
    });
    sites.insert(CallSite {
        callee: "system".to_string(),
        arg_count: 1,
    });
    let v = extract(&sites, AbstractionLevel::Typed);
    assert_eq!(v.level, AbstractionLevel::Typed);
    assert!(!v.primitive.is_empty());
    assert!(!v.typed.is_empty());
    assert!(v.typed.contains_key("unknown"));
    assert!(v.grouped.is_empty());
    assert!(v.semantic.is_empty());
}

#[test]
fn test_extract_grouped_level() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite {
        callee: "strcpy".to_string(),
        arg_count: 2,
    });
    sites.insert(CallSite {
        callee: "system".to_string(),
        arg_count: 1,
    });
    sites.insert(CallSite {
        callee: "printf".to_string(),
        arg_count: 1,
    });
    sites.insert(CallSite {
        callee: "malloc".to_string(),
        arg_count: 1,
    });
    let v = extract(&sites, AbstractionLevel::Grouped);
    assert_eq!(v.level, AbstractionLevel::Grouped);
    assert!(v.grouped.contains_key("memory"));
    assert!(v.grouped.contains_key("control_flow"));
    assert!(v.grouped.contains_key("I/O"));
    assert!(v.semantic.is_empty());
}

#[test]
fn test_extract_semantic_level() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite {
        callee: "strcpy".to_string(),
        arg_count: 2,
    });
    sites.insert(CallSite {
        callee: "system".to_string(),
        arg_count: 1,
    });
    sites.insert(CallSite {
        callee: "printf".to_string(),
        arg_count: 1,
    });
    let v = extract(&sites, AbstractionLevel::Semantic);
    assert_eq!(v.level, AbstractionLevel::Semantic);
    assert!(v.semantic.keys().any(|k| k.contains("buffer_overflow")));
    assert!(v.semantic.keys().any(|k| k.contains("command_injection")));
    assert!(!v.semantic.is_empty());
}

#[test]
fn test_extract_all_categorization_types() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite {
        callee: "strcpy".to_string(),
        arg_count: 2,
    });
    sites.insert(CallSite {
        callee: "printf".to_string(),
        arg_count: 1,
    });
    sites.insert(CallSite {
        callee: "memcpy".to_string(),
        arg_count: 3,
    });
    sites.insert(CallSite {
        callee: "system".to_string(),
        arg_count: 1,
    });
    sites.insert(CallSite {
        callee: "custom_fn".to_string(),
        arg_count: 2,
    });
    let v = extract(&sites, AbstractionLevel::Grouped);
    assert!(v.grouped.contains_key("memory"));
    assert!(v.grouped.contains_key("I/O"));
    assert!(v.grouped.contains_key("control_flow"));
    assert!(v.grouped.contains_key("other"));
}

// ============================================================================
// AbstractionVector::to_prompt_section() tests
// ============================================================================

#[test]
fn test_to_prompt_section_primitive_no_typed_grouped_semantic() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite {
        callee: "printf".to_string(),
        arg_count: 1,
    });
    let v = extract(&sites, AbstractionLevel::Primitive);
    let section = v.to_prompt_section();
    assert!(section.contains("%%PACVD_CONTEXT%%"));
    assert!(section.contains("(abstraction level: Primitive)"));
    assert!(section.contains("### Primitive API calls"));
    assert!(section.contains("printf"));
    assert!(!section.contains("### Typed grouping"));
    assert!(!section.contains("### Functional grouping"));
    assert!(!section.contains("### CWE-relevant tags"));
}

#[test]
fn test_to_prompt_section_typed_includes_typed() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite {
        callee: "printf".to_string(),
        arg_count: 1,
    });
    let v = extract(&sites, AbstractionLevel::Typed);
    let section = v.to_prompt_section();
    assert!(section.contains("### Primitive API calls"));
    assert!(section.contains("### Typed grouping"));
    assert!(!section.contains("### Functional grouping"));
    assert!(!section.contains("### CWE-relevant tags"));
}

#[test]
fn test_to_prompt_section_grouped_includes_grouped() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite {
        callee: "printf".to_string(),
        arg_count: 1,
    });
    let v = extract(&sites, AbstractionLevel::Grouped);
    let section = v.to_prompt_section();
    assert!(section.contains("### Primitive API calls"));
    assert!(section.contains("### Typed grouping"));
    assert!(section.contains("### Functional grouping"));
    assert!(!section.contains("### CWE-relevant tags"));
}

#[test]
fn test_to_prompt_section_semantic_all_sections() {
    let mut sites = BTreeSet::new();
    sites.insert(CallSite {
        callee: "strcpy".to_string(),
        arg_count: 2,
    });
    sites.insert(CallSite {
        callee: "system".to_string(),
        arg_count: 1,
    });
    let v = extract(&sites, AbstractionLevel::Semantic);
    let section = v.to_prompt_section();
    assert!(section.contains("%%PACVD_CONTEXT%%"));
    assert!(section.contains("(abstraction level: Semantic)"));
    assert!(section.contains("### Primitive API calls"));
    assert!(section.contains("### Typed grouping"));
    assert!(section.contains("### Functional grouping"));
    assert!(section.contains("### CWE-relevant tags"));
    assert!(section.contains("strcpy"));
    assert!(section.contains("system"));
}

// ============================================================================
// CallSite tests
// ============================================================================

#[test]
fn test_call_site_construction() {
    let site = CallSite {
        callee: "foo".to_string(),
        arg_count: 3,
    };
    assert_eq!(site.callee, "foo");
    assert_eq!(site.arg_count, 3);
}

#[test]
fn test_call_site_debug_format() {
    let site = CallSite {
        callee: "bar".to_string(),
        arg_count: 0,
    };
    let debug_str = format!("{:?}", site);
    assert!(debug_str.contains("bar"));
    assert!(debug_str.contains("0"));
}

#[test]
fn test_call_site_partial_eq() {
    let site1 = CallSite {
        callee: "foo".to_string(),
        arg_count: 2,
    };
    let site2 = CallSite {
        callee: "foo".to_string(),
        arg_count: 2,
    };
    let site3 = CallSite {
        callee: "bar".to_string(),
        arg_count: 2,
    };
    assert_eq!(site1, site2);
    assert_ne!(site1, site3);
}

// ============================================================================
// extract_call_sites() tests
// ============================================================================

#[test]
fn test_extract_call_sites_empty_source() {
    let sites = extract_call_sites("");
    assert!(sites.is_empty());
}

#[test]
fn test_extract_call_sites_no_calls() {
    let source = "let x = 42; let y = x + 1;";
    let sites = extract_call_sites(source);
    assert!(sites.is_empty());
}

#[test]
fn test_extract_call_sites_simple_call() {
    let sites = extract_call_sites("foo(1, 2, 3)");
    assert!(sites.contains(&CallSite {
        callee: "foo".to_string(),
        arg_count: 3,
    }));
}

#[test]
fn test_extract_call_sites_zero_args() {
    let sites = extract_call_sites("getpid()");
    assert!(sites.contains(&CallSite {
        callee: "getpid".to_string(),
        arg_count: 0,
    }));
}

#[test]
fn test_extract_call_sites_nested_calls() {
    let sites = extract_call_sites("outer(inner(1, 2), 3)");
    assert!(sites.contains(&CallSite {
        callee: "outer".to_string(),
        arg_count: 2,
    }));
    assert!(sites.contains(&CallSite {
        callee: "inner".to_string(),
        arg_count: 2,
    }));
}

#[test]
fn test_extract_call_sites_multiple_separate_calls() {
    let source = "foo(1);\nbar(2, 3);\nbaz();";
    let sites = extract_call_sites(source);
    assert!(sites.contains(&CallSite {
        callee: "foo".to_string(),
        arg_count: 1,
    }));
    assert!(sites.contains(&CallSite {
        callee: "bar".to_string(),
        arg_count: 2,
    }));
    assert!(sites.contains(&CallSite {
        callee: "baz".to_string(),
        arg_count: 0,
    }));
}

#[test]
fn test_extract_call_sites_deduplication() {
    let source = "foo(1);\nfoo(2);\nfoo(3);";
    let sites = extract_call_sites(source);
    let foo_count = sites.iter().filter(|s| s.callee == "foo").count();
    assert_eq!(foo_count, 1);
}

#[test]
fn test_extract_call_sites_complex_source() {
    let source = r#"
        let x = malloc(100);
        let y = strcpy(dest, src);
        printf("Result: %d", x);
        free(x);
    "#;
    let sites = extract_call_sites(source);
    assert!(sites.contains(&CallSite {
        callee: "malloc".to_string(),
        arg_count: 1,
    }));
    assert!(sites.contains(&CallSite {
        callee: "strcpy".to_string(),
        arg_count: 2,
    }));
    assert!(sites.contains(&CallSite {
        callee: "printf".to_string(),
        arg_count: 2,
    }));
    assert!(sites.contains(&CallSite {
        callee: "free".to_string(),
        arg_count: 1,
    }));
}

#[test]
fn test_extract_call_sites_with_brackets() {
    let sites = extract_call_sites("func(arr[0], arr[1])");
    assert!(sites.contains(&CallSite {
        callee: "func".to_string(),
        arg_count: 2,
    }));
}

// ============================================================================
// primitive_api tests
// ============================================================================

#[test]
fn test_lookup_malloc() {
    let vulns = lookup("malloc");
    assert!(vulns.contains(&PrimitiveApiVulnType::NullPointerDeref));
    assert!(vulns.contains(&PrimitiveApiVulnType::MemoryLeak));
    assert!(vulns.contains(&PrimitiveApiVulnType::UseAfterFree));
    assert!(vulns.contains(&PrimitiveApiVulnType::DoubleFree));
}

#[test]
fn test_lookup_free() {
    let vulns = lookup("free");
    assert!(vulns.contains(&PrimitiveApiVulnType::MemoryLeak));
    assert!(vulns.contains(&PrimitiveApiVulnType::UseAfterFree));
    assert!(vulns.contains(&PrimitiveApiVulnType::DoubleFree));
}

#[test]
fn test_lookup_open() {
    let vulns = lookup("open");
    assert_eq!(vulns, &[PrimitiveApiVulnType::ResourceLeak]);
}

#[test]
fn test_lookup_fclose() {
    let vulns = lookup("fclose");
    assert_eq!(vulns, &[PrimitiveApiVulnType::ResourceLeak]);
}

#[test]
fn test_lookup_realloc() {
    let vulns = lookup("realloc");
    assert!(vulns.contains(&PrimitiveApiVulnType::NullPointerDeref));
}

#[test]
fn test_lookup_calloc() {
    let vulns = lookup("calloc");
    assert!(vulns.contains(&PrimitiveApiVulnType::NullPointerDeref));
}

#[test]
fn test_lookup_unknown_api() {
    let vulns = lookup("nonexistent_function_xyz");
    assert!(vulns.is_empty());
}

#[test]
fn test_lookup_case_sensitive() {
    let vulns_lower = lookup("malloc");
    let vulns_upper = lookup("MALLOC");
    assert!(!vulns_lower.is_empty());
    assert!(vulns_upper.is_empty());
}

#[test]
fn test_primitive_api_table_not_empty() {
    assert!(!PRIMITIVE_API_TABLE.is_empty());
}

#[test]
fn test_primitive_api_table_has_expected_entries() {
    let table_names: Vec<&str> = PRIMITIVE_API_TABLE.iter().map(|e| e.name).collect();
    assert!(table_names.contains(&"malloc"));
    assert!(table_names.contains(&"free"));
    assert!(table_names.contains(&"open"));
    assert!(table_names.contains(&"close"));
    assert!(table_names.contains(&"fopen"));
}

#[test]
fn test_vuln_type_as_str_all_variants() {
    assert_eq!(PrimitiveApiVulnType::ResourceLeak.as_str(), "ResourceLeak");
    assert_eq!(
        PrimitiveApiVulnType::NullPointerDeref.as_str(),
        "NullPointerDeref"
    );
    assert_eq!(PrimitiveApiVulnType::MemoryLeak.as_str(), "MemoryLeak");
    assert_eq!(PrimitiveApiVulnType::UseAfterFree.as_str(), "UseAfterFree");
    assert_eq!(PrimitiveApiVulnType::DoubleFree.as_str(), "DoubleFree");
}

// ============================================================================
// Integration tests
// ============================================================================

#[test]
fn test_full_pipeline_empty_sites() {
    let source = "";
    let sites = extract_call_sites(source);
    let level = auto_level(1000);
    let vector = extract(&sites, level);
    let section = vector.to_prompt_section();
    assert!(section.contains("%%PACVD_CONTEXT%%"));
    assert!(vector.primitive.is_empty());
}

#[test]
fn test_full_pipeline_with_realistic_code() {
    let source = r#"
        FILE* fp = fopen("file.txt", "r");
        char* buf = malloc(1024);
        fgets(buf, 1024, fp);
        free(buf);
        fclose(fp);
    "#;
    let sites = extract_call_sites(source);
    let level = auto_level(32768);
    let vector = extract(&sites, level);
    let section = vector.to_prompt_section();
    assert!(section.contains("fopen"));
    assert!(section.contains("malloc"));
    assert!(section.contains("fclose"));
    assert!(section.contains("I/O"));
    assert!(section.contains("memory"));
}

#[test]
fn test_full_pipeline_semantic_extraction() {
    let source = r#"
        char* dst = malloc(100);
        strcpy(dst, src);
        system(cmd);
        free(dst);
    "#;
    let sites = extract_call_sites(source);
    let level = auto_level(128000);
    let vector = extract(&sites, level);
    assert_eq!(vector.level, AbstractionLevel::Semantic);
    let section = vector.to_prompt_section();
    assert!(section.contains("CWE-relevant tags"));
    assert!(section.contains("buffer_overflow"));
    assert!(section.contains("command_injection"));
}
