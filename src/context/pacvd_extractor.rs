//! PacVD primitive-API abstraction extractor (P4.3, P4.4).
//!
//! Computes a four-dimension abstraction vector from call sites:
//! 1. Primitive — raw callee names + arg counts
//! 2. Typed — callees grouped by inferred return type
//! 3. Grouped — callees grouped by functional category (I/O, crypto, etc.)
//! 4. Semantic — callees mapped to CWE-relevant tags
//!
//! Auto-level selection (P4.5): picks the abstraction level based on
//! the model's context window / max_tokens budget.

use super::callee_walker::CallSite;
use std::collections::{BTreeMap, BTreeSet};

/// Abstraction level (higher = more abstract).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AbstractionLevel {
    Primitive = 0,
    Typed = 1,
    Grouped = 2,
    Semantic = 3,
}

/// The four-dimension abstraction vector.
#[derive(Debug, Clone)]
pub struct AbstractionVector {
    pub level: AbstractionLevel,
    pub primitive: Vec<String>,
    pub typed: BTreeMap<String, Vec<String>>,
    pub grouped: BTreeMap<String, Vec<String>>,
    pub semantic: BTreeMap<String, Vec<String>>,
}

impl AbstractionVector {
    /// Format as a prompt section for the LLM.
    pub fn to_prompt_section(&self) -> String {
        let mut out = String::new();
        out.push_str("%%PACVD_CONTEXT%%\n");
        out.push_str(&format!("(abstraction level: {:?})\n\n", self.level));

        out.push_str("### Primitive API calls\n");
        for p in &self.primitive {
            out.push_str(&format!("- {}\n", p));
        }

        if self.level >= AbstractionLevel::Typed {
            out.push_str("\n### Typed grouping\n");
            for (ty, callees) in &self.typed {
                out.push_str(&format!("- {}: {}\n", ty, callees.join(", ")));
            }
        }

        if self.level >= AbstractionLevel::Grouped {
            out.push_str("\n### Functional grouping\n");
            for (cat, callees) in &self.grouped {
                out.push_str(&format!("- {}: {}\n", cat, callees.join(", ")));
            }
        }

        if self.level >= AbstractionLevel::Semantic {
            out.push_str("\n### CWE-relevant tags\n");
            for (tag, callees) in &self.semantic {
                out.push_str(&format!("- {}: {}\n", tag, callees.join(", ")));
            }
        }

        out
    }
}

pub fn categorize(callee: &str) -> &'static str {
    let c = callee.to_lowercase();
    if matches!(
        c.as_str(),
        "fopen"
            | "fclose"
            | "fread"
            | "fwrite"
            | "open"
            | "close"
            | "read"
            | "write"
            | "printf"
            | "fprintf"
            | "sprintf"
            | "scanf"
            | "fscanf"
            | "fgets"
            | "fputs"
            | "puts"
            | "getchar"
            | "putchar"
            | "getline"
    ) {
        "I/O"
    } else if matches!(
        c.as_str(),
        "memcpy"
            | "memset"
            | "memmove"
            | "strcpy"
            | "strncpy"
            | "strcat"
            | "strncat"
            | "strlen"
            | "strcmp"
            | "strncmp"
            | "malloc"
            | "calloc"
            | "realloc"
            | "free"
            | "alloca"
    ) {
        "memory"
    } else if matches!(
        c.as_str(),
        "strtok" | "strstr" | "strchr" | "strrchr" | "sscanf" | "snprintf" | "vsnprintf"
    ) {
        "string"
    } else if matches!(
        c.as_str(),
        "system" | "execve" | "execl" | "execvp" | "popen" | "fork" | "exec" | "eval"
    ) {
        "control_flow"
    } else if c.contains("crypt")
        || c.contains("hash")
        || c.contains("hmac")
        || c.contains("aes")
        || c.contains("rsa")
        || c.contains("sign")
        || c.contains("verify")
    {
        "crypto"
    } else if c.contains("db") || c.contains("query") || c.contains("sql") {
        "database"
    } else {
        "other"
    }
}

pub fn tag_cwe(callee: &str) -> Option<(&'static str, &'static str)> {
    let c = callee.to_lowercase();
    match c.as_str() {
        "strcpy" | "strcat" | "gets" | "sprintf" | "vsprintf" => {
            Some(("buffer_overflow", "CWE-120"))
        }
        "system" | "execve" | "execl" | "execvp" | "popen" => Some(("command_injection", "CWE-78")),
        "memcpy" | "memmove" => Some(("buffer_overflow", "CWE-119")),
        "malloc" | "calloc" | "realloc" => Some(("mem_mgmt", "CWE-416")),
        "free" => Some(("double_free", "CWE-415")),
        "strncpy" | "strncat" => Some(("off_by_one", "CWE-193")),
        _ => None,
    }
}

pub fn extract(sites: &BTreeSet<CallSite>, level: AbstractionLevel) -> AbstractionVector {
    let primitive: Vec<String> = sites
        .iter()
        .map(|c| format!("{}({} args)", c.callee, c.arg_count))
        .collect();

    let mut typed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if level >= AbstractionLevel::Typed {
        typed.entry("unknown".to_string()).or_default();
        for c in sites {
            typed
                .entry("unknown".to_string())
                .or_default()
                .push(c.callee.clone());
        }
    }

    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if level >= AbstractionLevel::Grouped {
        for c in sites {
            grouped
                .entry(categorize(&c.callee).to_string())
                .or_default()
                .push(c.callee.clone());
        }
    }

    let mut semantic: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if level >= AbstractionLevel::Semantic {
        for c in sites {
            if let Some((tag, _)) = tag_cwe(&c.callee) {
                semantic
                    .entry(format!("{} ({})", tag, c.callee))
                    .or_default()
                    .push(c.callee.clone());
            }
        }
    }

    AbstractionVector {
        level,
        primitive,
        typed,
        grouped,
        semantic,
    }
}

pub fn auto_level(max_context_tokens: usize) -> AbstractionLevel {
    if max_context_tokens <= 4096 {
        AbstractionLevel::Primitive
    } else if max_context_tokens <= 16384 {
        AbstractionLevel::Typed
    } else if max_context_tokens <= 65536 {
        AbstractionLevel::Grouped
    } else {
        AbstractionLevel::Semantic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn site(name: &str, n: usize) -> CallSite {
        CallSite {
            callee: name.into(),
            arg_count: n,
        }
    }

    fn sample_sites() -> BTreeSet<CallSite> {
        let mut s = BTreeSet::new();
        s.insert(site("strcpy", 2));
        s.insert(site("system", 1));
        s.insert(site("malloc", 1));
        s.insert(site("printf", 1));
        s
    }

    #[test]
    fn test_extract_primitive() {
        let v = extract(&sample_sites(), AbstractionLevel::Primitive);
        assert_eq!(v.level, AbstractionLevel::Primitive);
        assert_eq!(v.primitive.len(), 4);
        assert!(v.typed.is_empty());
        assert!(v.grouped.is_empty());
        assert!(v.semantic.is_empty());
    }

    #[test]
    fn test_extract_grouped() {
        let v = extract(&sample_sites(), AbstractionLevel::Grouped);
        assert!(v.grouped.contains_key("memory"));
        assert!(v.grouped.contains_key("control_flow"));
        assert!(v.grouped.contains_key("I/O"));
        assert!(v.semantic.is_empty());
    }

    #[test]
    fn test_extract_semantic() {
        let v = extract(&sample_sites(), AbstractionLevel::Semantic);
        assert!(v
            .semantic
            .iter()
            .any(|(k, _)| k.contains("buffer_overflow")));
        assert!(v
            .semantic
            .iter()
            .any(|(k, _)| k.contains("command_injection")));
    }

    #[test]
    fn test_auto_level_small() {
        assert_eq!(auto_level(2048), AbstractionLevel::Primitive);
    }

    #[test]
    fn test_auto_level_medium() {
        assert_eq!(auto_level(8192), AbstractionLevel::Typed);
    }

    #[test]
    fn test_auto_level_large() {
        assert_eq!(auto_level(32768), AbstractionLevel::Grouped);
    }

    #[test]
    fn test_auto_level_xl() {
        assert_eq!(auto_level(128000), AbstractionLevel::Semantic);
    }

    #[test]
    fn test_to_prompt_section_primitive() {
        let v = extract(&sample_sites(), AbstractionLevel::Primitive);
        let s = v.to_prompt_section();
        assert!(s.contains("%%PACVD_CONTEXT%%"));
        assert!(s.contains("strcpy"));
        assert!(!s.contains("### Functional grouping"));
    }

    #[test]
    fn test_to_prompt_section_semantic() {
        let v = extract(&sample_sites(), AbstractionLevel::Semantic);
        let s = v.to_prompt_section();
        assert!(s.contains("### CWE-relevant tags"));
    }

    #[test]
    fn test_categorize_known() {
        assert_eq!(categorize("strcpy"), "memory");
        assert_eq!(categorize("system"), "control_flow");
        assert_eq!(categorize("printf"), "I/O");
        assert_eq!(categorize("unknown_fn"), "other");
    }

    #[test]
    fn test_tag_cwe_known() {
        assert_eq!(tag_cwe("strcpy").unwrap().1, "CWE-120");
        assert_eq!(tag_cwe("system").unwrap().1, "CWE-78");
        assert!(tag_cwe("printf").is_none());
    }
}
