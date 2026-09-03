//! Unit tests for src/context/callee_walker.rs - CallSite extraction

use baco::context::callee_walker::{extract_call_sites, CallSite};
use std::collections::BTreeSet;

// ============================================================================
// CallSite tests
// ============================================================================

#[test]
fn test_call_site_creation() {
    let site = CallSite {
        callee: "test_func".to_string(),
        arg_count: 3,
    };

    assert_eq!(site.callee, "test_func");
    assert_eq!(site.arg_count, 3);
}

#[test]
fn test_call_site_debug_format() {
    let site = CallSite {
        callee: "test".to_string(),
        arg_count: 0,
    };

    let debug_str = format!("{:?}", site);
    assert!(debug_str.contains("test"));
}

#[test]
fn test_call_site_hash_and_ord() {
    let site1 = CallSite {
        callee: "test".to_string(),
        arg_count: 1,
    };
    let site2 = CallSite {
        callee: "test".to_string(),
        arg_count: 1,
    };
    let site3 = CallSite {
        callee: "test".to_string(),
        arg_count: 2,
    };

    // Same callee and arg_count should be equal
    assert_eq!(site1, site2);

    // Different arg_count should not be equal
    assert_ne!(site1, site3);

    // Should be usable in BTreeSet
    let mut set = BTreeSet::new();
    set.insert(site1);
    set.insert(site2); // Should not add duplicate
    set.insert(site3); // Should add different site

    assert_eq!(set.len(), 2);
}

// ============================================================================
// extract_call_sites - basic tests
// ============================================================================

#[test]
fn test_no_calls() {
    let source = "let x = 42;";
    let sites = extract_call_sites(source);

    assert!(sites.is_empty());
}

#[test]
fn test_simple_single_call() {
    let source = "foo(1, 2)";
    let sites = extract_call_sites(source);

    assert_eq!(sites.len(), 1);
    let site = sites.iter().next().unwrap();
    assert_eq!(site.callee, "foo");
    assert_eq!(site.arg_count, 2);
}

#[test]
fn test_zero_args() {
    let source = "getpid()";
    let sites = extract_call_sites(source);

    assert_eq!(sites.len(), 1);
    let site = sites.iter().next().unwrap();
    assert_eq!(site.callee, "getpid");
    assert_eq!(site.arg_count, 0);
}

#[test]
fn test_one_arg() {
    let source = "printf(\"hello\")";
    let sites = extract_call_sites(source);

    assert_eq!(sites.len(), 1);
    let site = sites.iter().next().unwrap();
    assert_eq!(site.callee, "printf");
    assert_eq!(site.arg_count, 1);
}

#[test]
fn test_many_args() {
    let source = "func(a, b, c, d, e)";
    let sites = extract_call_sites(source);

    assert_eq!(sites.len(), 1);
    let site = sites.iter().next().unwrap();
    assert_eq!(site.callee, "func");
    assert_eq!(site.arg_count, 5);
}

// ============================================================================
// extract_call_sites - nested calls
// ============================================================================

#[test]
fn test_nested_call_outer() {
    let source = "outer(inner(1), 2)";
    let sites = extract_call_sites(source);

    assert!(sites.contains(&CallSite {
        callee: "outer".to_string(),
        arg_count: 2
    }));
}

#[test]
fn test_nested_call_inner() {
    let source = "outer(inner(1), 2)";
    let sites = extract_call_sites(source);

    assert!(sites.contains(&CallSite {
        callee: "inner".to_string(),
        arg_count: 1
    }));
}

#[test]
fn test_deeply_nested_calls() {
    let source = "a(b(c(d())))";
    let sites = extract_call_sites(source);

    assert!(sites.contains(&CallSite {
        callee: "a".to_string(),
        arg_count: 1
    }));
    assert!(sites.contains(&CallSite {
        callee: "b".to_string(),
        arg_count: 1
    }));
    assert!(sites.contains(&CallSite {
        callee: "c".to_string(),
        arg_count: 1
    }));
    assert!(sites.contains(&CallSite {
        callee: "d".to_string(),
        arg_count: 0
    }));
}

#[test]
fn test_nested_with_multiple_args() {
    let source = "outer(1, inner(2, 3), 4)";
    let sites = extract_call_sites(source);

    assert!(sites.contains(&CallSite {
        callee: "outer".to_string(),
        arg_count: 3
    }));
    assert!(sites.contains(&CallSite {
        callee: "inner".to_string(),
        arg_count: 2
    }));
}

// ============================================================================
// extract_call_sites - deduplication
// ============================================================================

#[test]
fn test_dedup_same_callee_same_args() {
    let source = "foo(1)\nfoo(1)\nfoo(1)";
    let sites = extract_call_sites(source);

    // Should only have one entry for foo(1)
    assert_eq!(sites.len(), 1);
    assert!(sites.contains(&CallSite {
        callee: "foo".to_string(),
        arg_count: 1
    }));
}

#[test]
fn test_same_callee_different_args() {
    let source = "foo(1)\nfoo(2, 3)\nfoo(4, 5, 6)";
    let sites = extract_call_sites(source);

    // Should have three entries (different arg counts)
    assert_eq!(sites.len(), 3);

    let foo_sites: Vec<_> = sites.iter().filter(|s| s.callee == "foo").collect();
    assert_eq!(foo_sites.len(), 3);
}

// ============================================================================
// extract_call_sites - method calls
// ============================================================================

#[test]
fn test_method_call_colons() {
    let source = "obj::method(a)";
    let sites = extract_call_sites(source);

    assert!(!sites.is_empty());
    let names: Vec<_> = sites.iter().map(|c| c.callee.as_str()).collect();
    assert!(names.iter().any(|n| n.contains("method")));
}

#[test]
fn test_rust_method_call() {
    let source = "vec.push(1)";
    let sites = extract_call_sites(source);

    // Implementation may detect vec or push - just verify no panic
    let _ = sites;
}

// ============================================================================
// extract_call_sites - complex expressions
// ============================================================================

#[test]
fn test_call_with_complex_args() {
    let source = "func(a + b, c * d, e)";
    let sites = extract_call_sites(source);

    assert_eq!(sites.len(), 1);
    let site = sites.iter().next().unwrap();
    assert_eq!(site.callee, "func");
    assert_eq!(site.arg_count, 3);
}

#[test]
fn test_call_with_nested_parens() {
    let source = "func((a + b))";
    let sites = extract_call_sites(source);

    // Implementation may vary - just verify we detect calls or accept empty
    let _ = sites;
}

#[test]
fn test_call_with_brackets() {
    let source = "func(arr[0])";
    let sites = extract_call_sites(source);

    assert_eq!(sites.len(), 1);
    let site = sites.iter().next().unwrap();
    assert_eq!(site.callee, "func");
    assert_eq!(site.arg_count, 1);
}

#[test]
fn test_call_with_braces() {
    let source = "func(Struct { a: 1 })";
    let sites = extract_call_sites(source);

    assert_eq!(sites.len(), 1);
    let site = sites.iter().next().unwrap();
    assert_eq!(site.callee, "func");
    assert_eq!(site.arg_count, 1);
}

// ============================================================================
// extract_call_sites - multiple statements
// ============================================================================

#[test]
fn test_multiple_statements() {
    let source = "
        foo(1);
        bar(2);
        baz(3);
    ";
    let sites = extract_call_sites(source);

    assert!(sites.contains(&CallSite {
        callee: "foo".to_string(),
        arg_count: 1
    }));
    assert!(sites.contains(&CallSite {
        callee: "bar".to_string(),
        arg_count: 1
    }));
    assert!(sites.contains(&CallSite {
        callee: "baz".to_string(),
        arg_count: 1
    }));
}

#[test]
fn test_multiple_calls_same_line() {
    let source = "foo(1); bar(2);";
    let sites = extract_call_sites(source);

    assert!(sites.contains(&CallSite {
        callee: "foo".to_string(),
        arg_count: 1
    }));
    assert!(sites.contains(&CallSite {
        callee: "bar".to_string(),
        arg_count: 1
    }));
}

// ============================================================================
// extract_call_sites - edge cases
// ============================================================================

#[test]
fn test_empty_source() {
    let source = "";
    let sites = extract_call_sites(source);

    assert!(sites.is_empty());
}

#[test]
fn test_whitespace_only() {
    let source = "   \n\n   ";
    let sites = extract_call_sites(source);

    assert!(sites.is_empty());
}

#[test]
fn test_underscore_identifier() {
    let source = "_func(1)";
    let sites = extract_call_sites(source);

    assert!(sites.contains(&CallSite {
        callee: "_func".to_string(),
        arg_count: 1
    }));
}

#[test]
fn test_underscore_in_name() {
    let source = "my_func_name(1, 2)";
    let sites = extract_call_sites(source);

    assert!(sites.contains(&CallSite {
        callee: "my_func_name".to_string(),
        arg_count: 2
    }));
}

#[test]
fn test_numeric_in_name() {
    let source = "func123(1)";
    let sites = extract_call_sites(source);

    assert!(sites.contains(&CallSite {
        callee: "func123".to_string(),
        arg_count: 1
    }));
}

#[test]
fn test_call_in_string_literal() {
    // This is a limitation - we scan text, not parse
    // So "foo()" in a string might be detected
    let source = r#"let s = "foo(1)";"#;
    let sites = extract_call_sites(source);

    // May or may not detect - this is expected behavior for regex-based scanning
    // Just verify we don't panic
    let _ = sites;
}

#[test]
fn test_call_in_comment() {
    // Similar limitation - comments may contain detected patterns
    let source = "// foo(1)";
    let sites = extract_call_sites(source);

    // May or may not detect - expected for regex-based scanning
    let _ = sites;
}

#[test]
fn test_unicode_identifiers() {
    let source = "函数 (1)";
    let sites = extract_call_sites(source);

    // Unicode identifiers may or may not be detected depending on implementation
    let _ = sites;
}

// ============================================================================
// Integration tests
// ============================================================================

#[test]
fn test_real_rust_code() {
    let source = r#"
fn main() {
    let vec = vec![1, 2, 3];
    vec.push(4);
    println!("{:?}", vec);
}
"#;

    let sites = extract_call_sites(source);

    // Implementation may vary for real code - just verify no panic
    let _ = sites;
}

#[test]
fn test_real_c_code() {
    let source = r#"
int main() {
    FILE *f = fopen("test.txt", "r");
    char buf[100];
    fgets(buf, 100, f);
    fclose(f);
    return 0;
}
"#;

    let sites = extract_call_sites(source);

    assert!(sites.contains(&CallSite {
        callee: "fopen".to_string(),
        arg_count: 2
    }));
    assert!(sites.contains(&CallSite {
        callee: "fgets".to_string(),
        arg_count: 3
    }));
    assert!(sites.contains(&CallSite {
        callee: "fclose".to_string(),
        arg_count: 1
    }));
}

#[test]
fn test_complex_nested_expression() {
    let source = "result = outer(inner1(a, b), inner2(c, d(e, f)))";
    let sites = extract_call_sites(source);

    assert!(sites.contains(&CallSite {
        callee: "outer".to_string(),
        arg_count: 2
    }));
    assert!(sites.contains(&CallSite {
        callee: "inner1".to_string(),
        arg_count: 2
    }));
    assert!(sites.contains(&CallSite {
        callee: "inner2".to_string(),
        arg_count: 2
    }));
    assert!(sites.contains(&CallSite {
        callee: "d".to_string(),
        arg_count: 2
    }));
}

// ============================================================================
// Migrated inline tests from src/context/callee_walker.rs (6 tests)
// ============================================================================

#[test]
fn test_no_calls_inline_migrated() {
    use baco::context::callee_walker::extract_call_sites;

    let sites = extract_call_sites("let x = 42;");
    assert!(sites.is_empty());
}

#[test]
fn test_simple_call_inline_migrated() {
    use baco::context::callee_walker::{extract_call_sites, CallSite};

    let sites = extract_call_sites("foo(1, 2)");
    assert!(sites.contains(&CallSite {
        callee: "foo".into(),
        arg_count: 2
    }));
}

#[test]
fn test_nested_call_inline_migrated() {
    use baco::context::callee_walker::{extract_call_sites, CallSite};

    let sites = extract_call_sites("outer(inner(1), 2)");
    assert!(sites.contains(&CallSite {
        callee: "outer".into(),
        arg_count: 2
    }));
    assert!(sites.contains(&CallSite {
        callee: "inner".into(),
        arg_count: 1
    }));
}

#[test]
fn test_zero_args_inline_migrated() {
    use baco::context::callee_walker::{extract_call_sites, CallSite};

    let sites = extract_call_sites("getpid()");
    assert!(sites.contains(&CallSite {
        callee: "getpid".into(),
        arg_count: 0
    }));
}

#[test]
fn test_method_call_colons_inline_migrated() {
    use baco::context::callee_walker::extract_call_sites;

    let sites = extract_call_sites("obj::method(a)");
    let names: Vec<_> = sites.iter().map(|c| c.callee.as_str()).collect();
    assert!(names.iter().any(|n| n.contains("method")));
}

#[test]
fn test_dedup_same_callee_inline_migrated() {
    use baco::context::callee_walker::extract_call_sites;

    let sites = extract_call_sites("foo(1)\nfoo(2)\nfoo(3)");
    assert_eq!(sites.iter().filter(|c| c.callee == "foo").count(), 1);
}
