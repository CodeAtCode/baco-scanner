//! Callee walker for PacVD primitive-API abstraction (P4.2).
//!
//! Walks a source file's AST and extracts every function call site:
//! (callee_name, arg_count). The PacVD extractor uses this to compute
//! the four-dimension abstraction vector.

use std::collections::BTreeSet;

/// A single call site: callee name + argument count.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CallSite {
    pub callee: String,
    pub arg_count: usize,
}

/// Extract all call sites from source code.
///
/// Uses a lightweight syntactic scan (regex-based) to find `ident(args)`
/// patterns. This avoids pulling in tree-sitter grammars at this layer;
/// the tradeoff is that it may miss calls in unusual syntax (e.g., method
/// calls on complex expressions). Sufficient for the PacVD abstraction
/// dimension which only needs aggregate counts.
pub fn extract_call_sites(source: &str) -> BTreeSet<CallSite> {
    let mut sites = BTreeSet::new();
    let chars: Vec<(usize, char)> = source.char_indices().collect();
    let mut i = 0;

    while i < chars.len() {
        let (_, c) = chars[i];
        if c.is_alphabetic() || c == '_' {
            let mut name = String::new();
            name.push(c);
            i += 1;

            while i < chars.len() {
                let next = chars[i].1;
                if next.is_alphanumeric() || next == '_' || next == ':' {
                    name.push(next);
                    i += 1;
                } else {
                    break;
                }
            }

            while i < chars.len() && chars[i].1.is_whitespace() {
                i += 1;
            }

            if i < chars.len() && chars[i].1 == '(' {
                // Save position to continue scanning after this call
                let start_pos = i;
                i += 1;
                let arg_count = count_args(&chars, &mut i);
                sites.insert(CallSite {
                    callee: name.trim_end_matches(':').to_string(),
                    arg_count,
                });
                // Continue scanning inside the arguments for nested calls
                scan_for_calls(&chars, start_pos + 1, i - 1, &mut sites);
            }
        } else {
            i += 1;
        }
    }

    sites
}

fn scan_for_calls(
    chars: &[(usize, char)],
    start: usize,
    end: usize,
    sites: &mut BTreeSet<CallSite>,
) {
    let mut i = start;
    while i < end && i < chars.len() {
        let (_, c) = chars[i];
        if c.is_alphabetic() || c == '_' {
            let mut name = String::new();
            name.push(c);
            i += 1;

            while i < chars.len() && i < end {
                let next = chars[i].1;
                if next.is_alphanumeric() || next == '_' || next == ':' {
                    name.push(next);
                    i += 1;
                } else {
                    break;
                }
            }

            while i < chars.len() && i < end && chars[i].1.is_whitespace() {
                i += 1;
            }

            if i < chars.len() && i < end && chars[i].1 == '(' {
                let start_pos = i;
                i += 1;
                let arg_count = count_args(chars, &mut i);
                sites.insert(CallSite {
                    callee: name.trim_end_matches(':').to_string(),
                    arg_count,
                });
                // Recursively scan for deeper nesting
                scan_for_calls(chars, start_pos + 1, i - 1, sites);
            }
        } else {
            i += 1;
        }
    }
}

fn count_args(chars: &[(usize, char)], pos: &mut usize) -> usize {
    let mut depth = 1;
    let mut count = 0;
    let mut seen_content = false;

    while *pos < chars.len() {
        let c = chars[*pos].1;
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    *pos += 1;
                    break;
                }
            }
            ',' if depth == 1 => {
                count += 1;
            }
            _ if depth == 1 && !c.is_whitespace() => {
                seen_content = true;
            }
            _ => {}
        }
        *pos += 1;
    }

    if count > 0 {
        count + 1
    } else if seen_content {
        1
    } else {
        0
    }
}
