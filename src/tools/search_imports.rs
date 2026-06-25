//! Search imports tool.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchImportsArgs {
    pub module_name: String,
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportStatement {
    pub file_path: String,
    pub import_statement: String,
}

pub fn search_imports(args: SearchImportsArgs, target_path: &Path) -> Result<Vec<ImportStatement>, Box<dyn std::error::Error>> {
    let search_path = args.file_path
        .map(|p| target_path.join(p))
        .unwrap_or_else(|| target_path.to_path_buf());

    if !search_path.exists() {
        return Err(format!("Path does not exist: {:?}", search_path).into());
    }

    let mut imports = Vec::new();
    let patterns = vec![
        format!(r"use\s+{}::", regex::escape(&args.module_name)),  // Rust
        format!(r"import\s+.*from\s+['\"]{}['\"]", regex::escape(&args.module_name)),  // JS/TS import
        format!(r"from\s+['\"]{}['\"]", regex::escape(&args.module_name)),  // JS/TS from
        format!(r"import\s+{}\s+", regex::escape(&args.module_name)),  // Python import
        format!(r"from\s+{}\s+import", regex::escape(&args.module_name)),  // Python from
        format!(r"import\s+\"{}\"", regex::escape(&args.module_name)),  // Go
        format!(r"#include\s+[<\"]{}[>\"]", regex::escape(&args.module_name)),  // C/C++
    ];

    for entry in walkdir::WalkDir::new(&search_path).into_iter().filter_entry(|e| {
        !e.path().is_dir() || e.depth() < 5
    }) {
        let entry = entry?;
        if !entry.path().is_file() {
            continue;
        }

        let content = match fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for mat in re.find_iter(&content) {
                    imports.push(ImportStatement {
                        file_path: entry.path().to_string_lossy().to_string(),
                        import_statement: mat.as_str().to_string(),
                    });
                }
            }
        }
    }

    Ok(imports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_search_imports_no_matches() {
        let temp_dir = TempDir::new().unwrap();
        let args = SearchImportsArgs {
            module_name: "nonexistent".to_string(),
            file_path: None,
        };
        let result = search_imports(args, temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_search_imports_with_matches() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("main.rs");
        fs::write(&test_file, "use serde::Serialize;").unwrap();
        
        let args = SearchImportsArgs {
            module_name: "serde".to_string(),
            file_path: None,
        };
        let result = search_imports(args, temp_dir.path());
        assert!(result.is_ok());
        let imports = result.unwrap();
        assert!(!imports.is_empty());
    }
}
