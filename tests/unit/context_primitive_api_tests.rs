//! Unit tests for src/context/primitive_api.rs - Primitive API catalogue

use baco::context::primitive_api::{lookup, PrimitiveApiVulnType, PRIMITIVE_API_TABLE};

// ============================================================================
// PrimitiveApiVulnType tests
// ============================================================================

#[test]
fn test_vuln_type_resource_leak() {
    assert_eq!(PrimitiveApiVulnType::ResourceLeak.as_str(), "ResourceLeak");
}

#[test]
fn test_vuln_type_null_pointer_deref() {
    assert_eq!(
        PrimitiveApiVulnType::NullPointerDeref.as_str(),
        "NullPointerDeref"
    );
}

#[test]
fn test_vuln_type_memory_leak() {
    assert_eq!(PrimitiveApiVulnType::MemoryLeak.as_str(), "MemoryLeak");
}

#[test]
fn test_vuln_type_use_after_free() {
    assert_eq!(PrimitiveApiVulnType::UseAfterFree.as_str(), "UseAfterFree");
}

#[test]
fn test_vuln_type_double_free() {
    assert_eq!(PrimitiveApiVulnType::DoubleFree.as_str(), "DoubleFree");
}

#[test]
fn test_vuln_type_debug_format() {
    let vuln = PrimitiveApiVulnType::MemoryLeak;
    let debug_str = format!("{:?}", vuln);
    assert_eq!(debug_str, "MemoryLeak");
}

#[test]
fn test_vuln_type_clone() {
    let vuln1 = PrimitiveApiVulnType::ResourceLeak;
    let vuln2 = vuln1;
    assert_eq!(vuln1, vuln2);
}

#[test]
fn test_vuln_type_copy() {
    let vuln1 = PrimitiveApiVulnType::DoubleFree;
    let vuln2 = vuln1; // Copy, not move
    assert_eq!(vuln1, vuln2);
}

// ============================================================================
// lookup tests
// ============================================================================

#[test]
fn test_lookup_free() {
    let vulns = lookup("free");

    assert!(vulns.contains(&PrimitiveApiVulnType::MemoryLeak));
    assert!(vulns.contains(&PrimitiveApiVulnType::UseAfterFree));
    assert!(vulns.contains(&PrimitiveApiVulnType::DoubleFree));
    assert_eq!(vulns.len(), 3);
}

#[test]
fn test_lookup_open() {
    let vulns = lookup("open");

    assert_eq!(vulns, &[PrimitiveApiVulnType::ResourceLeak]);
}

#[test]
fn test_lookup_socket() {
    let vulns = lookup("socket");

    assert_eq!(vulns, &[PrimitiveApiVulnType::ResourceLeak]);
}

#[test]
fn test_lookup_fopen() {
    let vulns = lookup("fopen");

    assert_eq!(vulns, &[PrimitiveApiVulnType::ResourceLeak]);
}

#[test]
fn test_lookup_fdopen() {
    let vulns = lookup("fdopen");

    assert_eq!(vulns, &[PrimitiveApiVulnType::ResourceLeak]);
}

#[test]
fn test_lookup_opendir() {
    let vulns = lookup("opendir");

    assert_eq!(vulns, &[PrimitiveApiVulnType::ResourceLeak]);
}

#[test]
fn test_lookup_close() {
    let vulns = lookup("close");

    assert_eq!(vulns, &[PrimitiveApiVulnType::ResourceLeak]);
}

#[test]
fn test_lookup_fclose() {
    let vulns = lookup("fclose");

    assert_eq!(vulns, &[PrimitiveApiVulnType::ResourceLeak]);
}

#[test]
fn test_lookup_closedir() {
    let vulns = lookup("closedir");

    assert_eq!(vulns, &[PrimitiveApiVulnType::ResourceLeak]);
}

#[test]
fn test_lookup_malloc() {
    let vulns = lookup("malloc");

    assert!(vulns.contains(&PrimitiveApiVulnType::NullPointerDeref));
    assert!(vulns.contains(&PrimitiveApiVulnType::MemoryLeak));
    assert!(vulns.contains(&PrimitiveApiVulnType::UseAfterFree));
    assert!(vulns.contains(&PrimitiveApiVulnType::DoubleFree));
    assert_eq!(vulns.len(), 4);
}

#[test]
fn test_lookup_realloc() {
    let vulns = lookup("realloc");

    assert_eq!(vulns, &[PrimitiveApiVulnType::NullPointerDeref]);
}

#[test]
fn test_lookup_calloc() {
    let vulns = lookup("calloc");

    assert_eq!(vulns, &[PrimitiveApiVulnType::NullPointerDeref]);
}

#[test]
fn test_lookup_localtime() {
    let vulns = lookup("localtime");

    assert_eq!(vulns, &[PrimitiveApiVulnType::NullPointerDeref]);
}

#[test]
fn test_lookup_unknown() {
    let vulns = lookup("nonexistent_api");

    assert!(vulns.is_empty());
}

#[test]
fn test_lookup_case_sensitive() {
    let vulns_lower = lookup("free");
    let vulns_upper = lookup("FREE");

    assert!(!vulns_lower.is_empty());
    assert!(vulns_upper.is_empty()); // Case sensitive
}

// ============================================================================
// PRIMITIVE_API_TABLE tests
// ============================================================================

#[test]
fn test_table_has_entries() {
    assert!(!PRIMITIVE_API_TABLE.is_empty());
}

#[test]
fn test_table_all_have_names() {
    for entry in PRIMITIVE_API_TABLE {
        assert!(!entry.name.is_empty());
    }
}

#[test]
fn test_table_all_have_vuln_types() {
    for entry in PRIMITIVE_API_TABLE {
        assert!(!entry.vuln_types.is_empty());
    }
}

#[test]
fn test_table_unique_names() {
    let names: Vec<_> = PRIMITIVE_API_TABLE.iter().map(|e| e.name).collect();
    let unique_names: std::collections::HashSet<_> = names.iter().collect();

    assert_eq!(
        names.len(),
        unique_names.len(),
        "All entries should have unique names"
    );
}

#[test]
fn test_table_total_vuln_coverage() {
    // Verify all vuln types are covered by at least one API
    let all_vulns = [
        PrimitiveApiVulnType::ResourceLeak,
        PrimitiveApiVulnType::NullPointerDeref,
        PrimitiveApiVulnType::MemoryLeak,
        PrimitiveApiVulnType::UseAfterFree,
        PrimitiveApiVulnType::DoubleFree,
    ];

    for vuln in all_vulns {
        let found = PRIMITIVE_API_TABLE
            .iter()
            .any(|e| e.vuln_types.contains(&vuln));
        assert!(
            found,
            "Vuln type {:?} should be covered by at least one API",
            vuln
        );
    }
}

#[test]
fn test_table_resource_leak_apis() {
    let resource_leak_apis: Vec<_> = PRIMITIVE_API_TABLE
        .iter()
        .filter(|e| e.vuln_types.contains(&PrimitiveApiVulnType::ResourceLeak))
        .collect();

    assert!(resource_leak_apis.len() >= 7); // open, socket, fopen, fdopen, opendir, close, fclose, closedir
}

#[test]
fn test_table_memory_management_apis() {
    let mem_apis: Vec<_> = PRIMITIVE_API_TABLE
        .iter()
        .filter(|e| {
            e.name == "malloc" || e.name == "free" || e.name == "realloc" || e.name == "calloc"
        })
        .collect();

    assert_eq!(mem_apis.len(), 4);
}

// ============================================================================
// Entry structure tests
// ============================================================================

#[test]
fn test_entry_debug_format() {
    let entry = PRIMITIVE_API_TABLE
        .iter()
        .find(|e| e.name == "free")
        .unwrap();
    let debug_str = format!("{:?}", entry);

    assert!(debug_str.contains("free"));
    assert!(debug_str.contains("MemoryLeak"));
}

#[test]
fn test_entry_clone() {
    let entry = PRIMITIVE_API_TABLE
        .iter()
        .find(|e| e.name == "malloc")
        .unwrap();
    let entry_clone = *entry; // Copy

    assert_eq!(entry.name, entry_clone.name);
    assert_eq!(entry.vuln_types, entry_clone.vuln_types);
}

// ============================================================================
// Integration tests
// ============================================================================

#[test]
fn test_lookup_all_table_entries() {
    for entry in PRIMITIVE_API_TABLE {
        let vulns = lookup(entry.name);
        assert_eq!(
            vulns, entry.vuln_types,
            "Lookup should return same vuln types as table"
        );
    }
}

#[test]
fn test_lookup_returns_static_slice() {
    let vulns1 = lookup("free");
    let vulns2 = lookup("malloc");

    // Both should be valid slices
    assert!(!vulns1.is_empty());
    assert!(!vulns2.is_empty());
}

#[test]
fn test_vuln_types_are_distinct() {
    let malloc_vulns = lookup("malloc");

    // Verify all vuln types in malloc entry are distinct
    let unique: std::collections::HashSet<_> = malloc_vulns.iter().collect();
    assert_eq!(malloc_vulns.len(), unique.len());
}

#[test]
fn test_resource_leak_only_for_io_apis() {
    let io_apis = [
        "open", "socket", "fopen", "fdopen", "opendir", "close", "fclose", "closedir",
    ];

    for api in io_apis {
        let vulns = lookup(api);
        assert!(vulns.contains(&PrimitiveApiVulnType::ResourceLeak));
        // Should only have ResourceLeak
        assert_eq!(vulns.len(), 1);
    }
}

#[test]
fn test_memory_apis_have_multiple_vuln_types() {
    let malloc_vulns = lookup("malloc");
    let free_vulns = lookup("free");

    assert!(
        malloc_vulns.len() > 1,
        "malloc should have multiple vuln types"
    );
    assert!(free_vulns.len() > 1, "free should have multiple vuln types");
}
