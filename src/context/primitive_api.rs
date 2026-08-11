//! Primitive API catalogue for PacVD context abstraction (P4).
//!
//! Maps primitive C/system APIs (malloc, free, open, close, ...) to the
//! vulnerability types they are associated with. Used by the four-dimension
//! extractor to build callee abstractions at four granularity levels.

/// Vulnerability types targeted by primitive-API abstraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrimitiveApiVulnType {
    ResourceLeak,
    NullPointerDeref,
    MemoryLeak,
    UseAfterFree,
    DoubleFree,
}

impl PrimitiveApiVulnType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ResourceLeak => "ResourceLeak",
            Self::NullPointerDeref => "NullPointerDeref",
            Self::MemoryLeak => "MemoryLeak",
            Self::UseAfterFree => "UseAfterFree",
            Self::DoubleFree => "DoubleFree",
        }
    }
}

/// A primitive API entry: the function name and the vuln types it covers.
#[derive(Debug, Clone, Copy)]
pub struct PrimitiveApiEntry {
    pub name: &'static str,
    pub vuln_types: &'static [PrimitiveApiVulnType],
}

/// The full primitive-API table from the PacVD paper (Table 1), extended
/// with language-specific APIs.
///
/// C/system APIs:
/// - open/socket/fopen/fdopen/opendir/close/fclose/closedir → Resource Leak
/// - malloc/realloc/calloc/localtime → Null Pointer Dereference
/// - malloc/free → Memory Leak, UAF, Double Free
///
/// Language-specific extensions:
/// - Python: open, os.system
/// - Java: FileInputStream, FileOutputStream
pub static PRIMITIVE_API_TABLE: &[PrimitiveApiEntry] = &[
    PrimitiveApiEntry {
        name: "open",
        vuln_types: &[PrimitiveApiVulnType::ResourceLeak],
    },
    PrimitiveApiEntry {
        name: "socket",
        vuln_types: &[PrimitiveApiVulnType::ResourceLeak],
    },
    PrimitiveApiEntry {
        name: "fopen",
        vuln_types: &[PrimitiveApiVulnType::ResourceLeak],
    },
    PrimitiveApiEntry {
        name: "fdopen",
        vuln_types: &[PrimitiveApiVulnType::ResourceLeak],
    },
    PrimitiveApiEntry {
        name: "opendir",
        vuln_types: &[PrimitiveApiVulnType::ResourceLeak],
    },
    PrimitiveApiEntry {
        name: "close",
        vuln_types: &[PrimitiveApiVulnType::ResourceLeak],
    },
    PrimitiveApiEntry {
        name: "fclose",
        vuln_types: &[PrimitiveApiVulnType::ResourceLeak],
    },
    PrimitiveApiEntry {
        name: "closedir",
        vuln_types: &[PrimitiveApiVulnType::ResourceLeak],
    },
    PrimitiveApiEntry {
        name: "malloc",
        vuln_types: &[
            PrimitiveApiVulnType::NullPointerDeref,
            PrimitiveApiVulnType::MemoryLeak,
            PrimitiveApiVulnType::UseAfterFree,
            PrimitiveApiVulnType::DoubleFree,
        ],
    },
    PrimitiveApiEntry {
        name: "realloc",
        vuln_types: &[PrimitiveApiVulnType::NullPointerDeref],
    },
    PrimitiveApiEntry {
        name: "calloc",
        vuln_types: &[PrimitiveApiVulnType::NullPointerDeref],
    },
    PrimitiveApiEntry {
        name: "localtime",
        vuln_types: &[PrimitiveApiVulnType::NullPointerDeref],
    },
    PrimitiveApiEntry {
        name: "free",
        vuln_types: &[
            PrimitiveApiVulnType::MemoryLeak,
            PrimitiveApiVulnType::UseAfterFree,
            PrimitiveApiVulnType::DoubleFree,
        ],
    },
];

/// Look up the vulnerability types associated with a primitive API by name.
/// Returns an empty slice if the name is not in the catalogue.
pub fn lookup(name: &str) -> &'static [PrimitiveApiVulnType] {
    PRIMITIVE_API_TABLE
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.vuln_types)
        .unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_lookup_unknown() {
        assert!(lookup("nonexistent_api").is_empty());
    }

    #[test]
    fn test_vuln_type_as_str() {
        assert_eq!(PrimitiveApiVulnType::ResourceLeak.as_str(), "ResourceLeak");
        assert_eq!(
            PrimitiveApiVulnType::NullPointerDeref.as_str(),
            "NullPointerDeref"
        );
    }
}
