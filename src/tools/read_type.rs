//! Read type definition tool.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs;
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadTypeArgs {
    pub type_name: String,
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDefinition {
    pub definition: String,
    pub file_path: String,
    pub line_number: u32,
    pub fields: Vec<String>,
}

pub fn read_type_definition(args: ReadTypeArgs, target_path: &Path) -> Result<TypeDefinition, Box<dyn std::error::Error>> {
    let search_path = args.file_path
        .map(|p| target_path.join(p))
        .unwrap_or_else(|| target_path.to_path_buf());

    if !search_path.exists() {
        return Err(format!("Path does not exist: {:?}", search_path).into());
    }

    let pattern = format!(r"(?:struct|enum|type|class)\s+{}\s*{{[^}}]*}}", regex::escape(&args.type_name));
    let re = Regex::new(&pattern)?;

    for entry in walkdir::WalkDir::new(&search_path)
        .into_iter()
        .filter_entry(|e| !e.path().is_dir() || e.depth() < 3)
    {
        let entry = entry?;
        if !entry.path().is_file() {
            continue;
        }

        let content = fs::read_to_string(entry.path())?;
        if let Some(mat) = re.find(&content) {
            let definition = mat.as_str().to_string();
            let line_number = content[..mat.start()].lines().count() as u32 + 1;
            let fields = extract_fields(&definition);

            return Ok(TypeDefinition {
                definition,
                file_path: entry.path().to_string_lossy().to_string(),
                line_number,
                fields,
            });
        }
    }

    Err(format!("Type {} not found", args.type_name).into())
}

fn extract_fields(definition: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let re = Regex::new(r"(\w+)\s*:\s*\w+").unwrap();
    for mat in re.find_iter(definition) {
        let field = mat.as_str().split(':').next().unwrap_or("").trim();
        if !field.is_empty() {
            fields.push(field.to_string());
        }
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_read_type_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let args = ReadTypeArgs {
            type_name: "NonExistent".to_string(),
            file_path: None,
        };
        let result = read_type_definition(args, temp_dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_read_type_found() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("types.rs");
        fs::write(&test_file, "struct User { name: String, age: u32 }").unwrap();
        
        let args = ReadTypeArgs {
            type_name: "User".to_string(),
            file_path: None,
        };
        let result = read_type_definition(args, temp_dir.path());
        assert!(result.is_ok());
        let def = result.unwrap();
        assert!(def.definition.contains("struct User"));
    }
}
