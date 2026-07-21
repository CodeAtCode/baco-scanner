//! Pre-built CPGQL queries per CWE family
//!
//! These are conservative query templates that should work across most codebases.
//! TODO: validate against live Joern installation.

/// Get CPGQL query template for a given CWE ID
///
/// Returns a query string that can be run against a CPG.
/// Falls back to a default query if the CWE is not recognized.
pub fn get_query_for_cwe(cwe_id: &str, entry_point: &str) -> String {
    // Normalize CWE ID (handle "CWE-79", "79", etc.)
    let normalized = normalize_cwe_id(cwe_id);

    match normalized.as_str() {
        // CWE-79: Cross-site scripting (XSS)
        // Find calls that might involve unsanitized output
        "79" | "cwe-79" => {
            // TODO: validate against live Joern
            "cpg.call(\".*sanitize.*\").argument.l".to_string()
        }

        // CWE-89: SQL Injection
        // Find execute/query calls with non-literal arguments
        "89" | "cwe-89" => {
            // TODO: validate against live Joern
            "cpg.call(\".*execute.*|.*query.*\").argument.whereNot(_.isLiteral).l".to_string()
        }

        // CWE-78: OS Command Injection
        // Find Process/exec calls
        "78" | "cwe-78" => {
            // TODO: validate against live Joern
            "cpg.call(\"Process.*|exec.*\").argument.l".to_string()
        }

        // CWE-22: Path Traversal
        // Find file open/read calls
        "22" | "cwe-22" => {
            // TODO: validate against live Joern
            "cpg.call(\".*open.*|.*read.*\").argument.l".to_string()
        }

        // CWE-502: Deserialization of Untrusted Data
        "502" | "cwe-502" => {
            // TODO: validate against live Joern
            "cpg.call(\".*deserialize.*|.*readObject.*\").l".to_string()
        }

        // CWE-798: Hardcoded Credentials
        "798" | "cwe-798" => {
            // TODO: validate against live Joern
            "cpg.identifier(\".*password.*|.*secret.*|.*apiKey.*\").l".to_string()
        }

        // CWE-200: Information Exposure
        "200" | "cwe-200" => {
            // TODO: validate against live Joern
            "cpg.call(\".*log.*|.*print.*\").argument.l".to_string()
        }

        // Default fallback: search for entry point function
        _ => {
            // TODO: validate against live Joern
            format!("cpg.method.name(\".*{}.*\").l", regex::escape(entry_point))
        }
    }
}

/// Normalize CWE ID to a standard format
fn normalize_cwe_id(cwe_id: &str) -> String {
    let id = cwe_id.trim().to_lowercase();

    // Already has CWE- prefix
    if id.starts_with("cwe-") {
        return id;
    }

    // Just the number
    if id.chars().all(|c| c.is_ascii_digit()) {
        return format!("cwe-{}", id);
    }

    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_query_for_cwe79() {
        let query = get_query_for_cwe("CWE-79", "main");
        assert!(query.contains("sanitize"));
    }

    #[test]
    fn test_get_query_for_cwe89() {
        let query = get_query_for_cwe("CWE-89", "main");
        assert!(query.contains("execute") || query.contains("query"));
    }

    #[test]
    fn test_get_query_for_cwe78() {
        let query = get_query_for_cwe("CWE-78", "main");
        assert!(query.contains("Process") || query.contains("exec"));
    }

    #[test]
    fn test_get_query_for_cwe22() {
        let query = get_query_for_cwe("CWE-22", "main");
        assert!(query.contains("open") || query.contains("read"));
    }

    #[test]
    fn test_get_query_fallback_for_unknown_cwe() {
        let query = get_query_for_cwe("CWE-999", "my_entry_point");
        assert!(query.contains("my_entry_point"));
    }

    #[test]
    fn test_normalize_cwe_id_with_prefix() {
        assert_eq!(normalize_cwe_id("CWE-79"), "cwe-79");
        assert_eq!(normalize_cwe_id("cwe-89"), "cwe-89");
    }

    #[test]
    fn test_normalize_cwe_id_without_prefix() {
        assert_eq!(normalize_cwe_id("79"), "cwe-79");
        assert_eq!(normalize_cwe_id("89"), "cwe-89");
    }

    #[test]
    fn test_normalize_cwe_id_with_whitespace() {
        assert_eq!(normalize_cwe_id("  CWE-79  "), "cwe-79");
    }
}
