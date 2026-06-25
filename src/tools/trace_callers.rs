//! Trace function callers tool.
//! Finds all call-sites of a function using grep.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCallersArgs {
    pub function_name: String,
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    pub file_path: String,
    pub line_number: u32,
    pub calling_function: String,
}

pub fn trace_function_callers(args: TraceCallersArgs, target_path: &Path) -> Result<Vec<CallSite>, Box<dyn std::error::Error>> {
    let search_path = args.file_path
        .map(|p| target_path.join(p))
        .unwrap_or_else(|| target_path.to_path_buf());

    if !search_path.exists() {
        return Err(format!("Path does not exist: {:?}", search_path).into());
    }

    // Use ripgrep if available, otherwise grep
    let output = Command::new("rg")
        .arg("--line-number")
        .arg("--no-heading")
        .arg(&args.function_name)
        .arg(&search_path)
        .output()
        .or_else(|_| {
            Command::new("grep")
                .arg("-n")
                .arg("-r")
                .arg(&args.function_name)
                .arg(&search_path)
                .output()
        })?;

    if !output.status.success() {
        return Ok(vec![]); // No matches found
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut call_sites = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            let file_path = parts[0].to_string();
            let line_number = parts[1].parse::<u32>().unwrap_or(0);
            let context = parts[2..].join(":");
            
            call_sites.push(CallSite {
                file_path,
                line_number,
                calling_function: context.trim().to_string(),
            });
        }
    }

    Ok(call_sites.into_iter().take(5).collect()) // Limit to max depth of 5
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_trace_callers_no_matches() {
        let temp_dir = TempDir::new().unwrap();
        let args = TraceCallersArgs {
            function_name: "nonexistent_function".to_string(),
            file_path: None,
        };
        let result = trace_function_callers(args, temp_dir.path());
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_trace_callers_with_matches() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.rs");
        fs::write(&test_file, "fn main() { process_input(); }\nfn process_input() {}\n").unwrap();
        
        let args = TraceCallersArgs {
            function_name: "process_input".to_string(),
            file_path: None,
        };
        let result = trace_function_callers(args, temp_dir.path());
        assert!(result.is_ok());
        let sites = result.unwrap();
        assert!(!sites.is_empty());
    }
}
