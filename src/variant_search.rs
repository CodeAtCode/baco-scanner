//! Variant Search Module
//!
//! Searches for code patterns that may represent variants of known vulnerabilities.
//! Uses regex-based pattern matching with similarity scoring.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VariantSearchError {
    #[error("Pattern error: {0}")]
    PatternError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, VariantSearchError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchPattern {
    pub vulnerability_type: String,
    pub code_pattern: String,
    pub context_keywords: Vec<String>,
}

impl SearchPattern {
    pub fn new(
        vulnerability_type: &str,
        code_pattern: &str,
        context_keywords: Vec<String>,
    ) -> Self {
        Self {
            vulnerability_type: vulnerability_type.to_string(),
            code_pattern: code_pattern.to_string(),
            context_keywords,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantHit {
    pub file_path: String,
    pub line_number: u32,
    pub similarity_score: f32,
    pub snippet: String,
}

impl VariantHit {
    pub fn new(file_path: &str, line_number: u32, similarity_score: f32, snippet: &str) -> Self {
        Self {
            file_path: file_path.to_string(),
            line_number,
            similarity_score,
            snippet: snippet.to_string(),
        }
    }
}

pub struct VariantSearcher {
    root_path: String,
    patterns: Vec<SearchPattern>,
    threshold: f32,
}

impl VariantSearcher {
    pub fn new(root_path: String) -> Self {
        Self {
            root_path,
            patterns: Vec::new(),
            threshold: 0.5,
        }
    }

    pub fn with_patterns(mut self, patterns: Vec<SearchPattern>) -> Self {
        self.patterns = patterns;
        self
    }

    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Search for variants matching registered patterns
    pub fn search_variants(&self) -> Result<Vec<VariantHit>> {
        let mut all_hits = Vec::new();

        for pattern in &self.patterns {
            let hits = self.search_for_pattern(pattern)?;
            all_hits.extend(hits);
        }

        let filtered: Vec<VariantHit> = all_hits
            .into_iter()
            .filter(|hit| hit.similarity_score >= self.threshold)
            .collect();

        Ok(filtered)
    }

    fn search_for_pattern(&self, pattern: &SearchPattern) -> Result<Vec<VariantHit>> {
        let regex = regex::Regex::new(&pattern.code_pattern)
            .map_err(|e| VariantSearchError::PatternError(e.to_string()))?;

        let mut hits = Vec::new();
        let skip_dirs = vec!["target", "node_modules", ".git", "dist", "build"];

        self.search_directory(&self.root_path, &regex, pattern, &skip_dirs, &mut hits)?;

        Ok(hits)
    }

    fn search_directory(
        &self,
        dir: &str,
        regex: &regex::Regex,
        pattern: &SearchPattern,
        skip_dirs: &[&str],
        hits: &mut Vec<VariantHit>,
    ) -> Result<()> {
        let entries = fs::read_dir(dir)?;

        for entry in entries.flatten() {
            let path = entry.path();
            let path_str = path.to_string_lossy().to_string();

            if path.is_dir() {
                let dir_name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                if skip_dirs.contains(&dir_name.as_str()) {
                    continue;
                }

                self.search_directory(&path_str, regex, pattern, skip_dirs, hits)?;
            } else if path.is_file() {
                if Self::should_skip_file(&path) {
                    continue;
                }

                if let Ok(content) = fs::read_to_string(&path) {
                    for (line_num, line) in content.lines().enumerate() {
                        if regex.is_match(line) {
                            let similarity = self.calculate_similarity(line, pattern);
                            let snippet = Self::extract_snippet(&content, line_num);

                            hits.push(VariantHit::new(
                                &path_str,
                                line_num as u32 + 1,
                                similarity,
                                &snippet,
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn should_skip_file(path: &Path) -> bool {
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        matches!(
            ext.as_str(),
            "bin"
                | "so"
                | "dll"
                | "dylib"
                | "exe"
                | "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "ico"
                | "pdf"
                | "zip"
                | "tar"
                | "gz"
                | "rar"
                | "lock"
                | "sum"
                | "md5"
                | "sha"
        )
    }

    pub fn extract_snippet(content: &str, line_num: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        if lines.is_empty() {
            return String::new();
        }
        let start = line_num
            .saturating_sub(1)
            .min(lines.len().saturating_sub(1));
        let end = (line_num + 2).min(lines.len());
        if start >= end {
            return String::new();
        }
        lines[start..end].join("\n")
    }

    pub fn calculate_similarity(&self, line: &str, pattern: &SearchPattern) -> f32 {
        let mut score: f32 = 0.0;

        if line.contains(&pattern.vulnerability_type) {
            score += 0.4;
        }

        if !pattern.code_pattern.is_empty() {
            score += 0.3;
        }

        for keyword in &pattern.context_keywords {
            if line.to_lowercase().contains(&keyword.to_lowercase()) {
                score += 0.15;
            }
        }

        score.min(1.0)
    }

    /// Extract a regex pattern from code (simplified version)
    pub fn extract_pattern(code_sample: &str) -> String {
        let mut pattern = code_sample.to_string();

        pattern = pattern.replace(".", "\\.");
        pattern = pattern.replace("*", ".*");
        pattern = pattern.replace("+", "\\+");
        pattern = pattern.replace("?", "\\?");
        pattern = pattern.replace("(", "\\(");
        pattern = pattern.replace(")", "\\)");
        pattern = pattern.replace("[", "\\[");
        pattern = pattern.replace("]", "\\]");

        pattern
    }

    /// Match a line against a pattern
    pub fn match_pattern(line: &str, pattern_str: &str) -> bool {
        match regex::Regex::new(pattern_str) {
            Ok(regex) => regex.is_match(line),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_files() -> TempDir {
        let temp = TempDir::new().unwrap();

        fs::write(
            temp.path().join("main.rs"),
            r#"
fn vulnerable_func() {
    let cmd = user_input();
    std::process::Command::new(cmd).spawn();
}
"#,
        )
        .unwrap();

        fs::write(
            temp.path().join("utils.rs"),
            r#"
fn safe_function() {

}
"#,
        )
        .unwrap();

        fs::write(
            temp.path().join("test.py"),
            r#"
import os
os.system(user_input)
"#,
        )
        .unwrap();

        temp
    }

    #[test]
    fn test_search_finds_vulnerable_pattern() {
        let temp = create_test_files();

        let searcher = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
            .with_patterns(vec![SearchPattern::new(
                "command_injection",
                r"Command::new\(.*\).*spawn\(\)",
                vec!["user_input".to_string(), "process".to_string()],
            )])
            .with_threshold(0.3);

        let hits = searcher.search_variants().unwrap();

        assert!(!hits.is_empty());

        let has_command_injection = hits.iter().any(|h| h.file_path.contains("main.rs"));
        assert!(has_command_injection);

        drop(temp);
    }

    #[test]
    fn test_binary_files_skipped() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0u8; 100]).unwrap();

        let searcher = VariantSearcher::new(
            temp_file
                .path()
                .parent()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        );

        // Should not crash on binary files
        let result = searcher.search_variants();
        assert!(result.is_ok());
    }

    #[test]
    fn test_node_modules_skipped() {
        let temp = TempDir::new().unwrap();

        let node_modules = temp.path().join("node_modules");
        fs::create_dir_all(&node_modules).unwrap();
        fs::write(node_modules.join("evil.js"), "malicious code").unwrap();

        let searcher = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
            .with_patterns(vec![SearchPattern::new("test", ".*", vec![])]);

        let hits = searcher.search_variants().unwrap();

        // node_modules should be skipped

        // Should not find anything in node_modules
        let from_node_modules = hits.iter().any(|h| h.file_path.contains("node_modules"));
        assert!(!from_node_modules);

        drop(temp);
    }

    #[test]
    fn test_threshold_filters_results() {
        let temp = create_test_files();

        let searcher = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
            .with_patterns(vec![SearchPattern::new(
                "test",
                ".*",
                vec!["test".to_string()],
            )])
            .with_threshold(0.9);

        let hits = searcher.search_variants().unwrap();

        for hit in &hits {
            assert!(hit.similarity_score >= 0.9);
        }

        drop(temp);
    }

    #[test]
    fn test_extract_pattern() {
        let pattern = VariantSearcher::extract_pattern("user.name");
        assert!(pattern.contains("\\."));

        let pattern2 = VariantSearcher::extract_pattern("func(arg)");
        assert!(pattern2.contains("\\("));
        assert!(pattern2.contains("\\)"));
    }

    #[test]
    fn test_match_pattern() {
        assert!(VariantSearcher::match_pattern("let x = foo();", r"foo\(\)"));
        assert!(!VariantSearcher::match_pattern(
            "let x = bar();",
            r"foo\(\)"
        ));
    }

    #[test]
    fn test_invalid_regex_handled() {
        let result = VariantSearcher::match_pattern("test", "[invalid(");
        assert!(!result);
    }

    #[test]
    fn test_snippet_extraction() {
        let content = "line1\nline2\nline3\nline4\nline5";

        let snippet = VariantSearcher::extract_snippet(content, 1);
        assert!(snippet.contains("line2"));
    }

    #[test]
    fn test_similarity_scoring() {
        use tempfile::NamedTempFile;
        let temp_file = NamedTempFile::new().unwrap();

        let searcher = VariantSearcher::new(
            temp_file
                .path()
                .parent()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        );

        let pattern = SearchPattern::new(
            "command_injection",
            r"Command::new\(",
            vec!["user_input".to_string(), "spawn".to_string()],
        );

        let line1 = "let cmd = Command::new(user_input).spawn()";
        let score1 = searcher.calculate_similarity(line1, &pattern);

        let line2 = "let cmd = Command::new(\"ls\")";
        let score2 = searcher.calculate_similarity(line2, &pattern);

        assert!(score1 > score2);
    }
}
