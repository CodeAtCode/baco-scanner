//! BM25 ranking algorithm implementation for CWE specification retrieval.
//!
//! This module provides a standalone BM25 implementation without external crates.

use std::collections::HashMap;

/// Tokenized document with term frequencies
#[derive(Debug, Clone)]
pub struct TokenizedDoc {
    pub tokens: Vec<String>,
    pub term_freqs: HashMap<String, usize>,
}

/// BM25 index for ranked retrieval
#[derive(Debug)]
pub struct Bm25Index {
    docs: Vec<TokenizedDoc>,
    avg_doc_len: f64,
    k1: f64,
    b: f64,
}

impl Bm25Index {
    /// Create a new BM25 index from document texts.
    ///
    /// # Arguments
    /// * `docs` - Vector of document texts to index
    /// * `k1` - Term frequency saturation parameter (default 1.2)
    /// * `b` - Length normalization parameter (default 0.75)
    pub fn new(docs: Vec<&str>, k1: f64, b: f64) -> Self {
        let tokenized: Vec<TokenizedDoc> = docs.iter().map(|text| Self::tokenize(text)).collect();

        let avg_doc_len = if tokenized.is_empty() {
            0.0
        } else {
            tokenized.iter().map(|d| d.tokens.len() as f64).sum::<f64>() / tokenized.len() as f64
        };

        Bm25Index {
            docs: tokenized,
            avg_doc_len,
            k1,
            b,
        }
    }

    /// Tokenize text by splitting on whitespace/punctuation and lowercasing
    fn tokenize(text: &str) -> TokenizedDoc {
        let tokens: Vec<String> = text
            .to_lowercase()
            .split(|c: char| c.is_whitespace() || !c.is_alphanumeric())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        let mut term_freqs: HashMap<String, usize> = HashMap::new();
        for token in &tokens {
            *term_freqs.entry(token.clone()).or_insert(0) += 1;
        }

        TokenizedDoc { tokens, term_freqs }
    }

    /// Calculate IDF for a term using standard BM25 formulation
    fn idf(&self, term: &str) -> f64 {
        let n = self
            .docs
            .iter()
            .filter(|d| d.term_freqs.contains_key(term))
            .count() as f64;
        if n == 0.0 {
            0.0
        } else {
            (self.docs.len() as f64 - n + 0.5) / (n + 0.5)
        }
    }

    /// Search for documents matching the query, returning top-k indices by BM25 score
    ///
    /// # Arguments
    /// * `query` - Search query text
    /// * `k` - Maximum number of results to return
    ///
    /// # Returns
    /// Vector of document indices ranked by BM25 score (highest first)
    pub fn search(&self, query: &str, k: usize) -> Vec<usize> {
        if query.trim().is_empty() || self.docs.is_empty() {
            return Vec::new();
        }

        let query_tokens: Vec<String> = query
            .to_lowercase()
            .split(|c: char| c.is_whitespace() || !c.is_alphanumeric())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        let mut scores: Vec<(usize, f64)> = self
            .docs
            .iter()
            .enumerate()
            .map(|(i, doc)| {
                let mut score = 0.0;
                for q_token in &query_tokens {
                    if let Some(&tf) = doc.term_freqs.get(q_token) {
                        let idf = self.idf(q_token);
                        let numerator = (tf as f64) * (self.k1 + 1.0);
                        let denominator = (tf as f64)
                            + self.k1
                                * (1.0 - self.b
                                    + self.b * (doc.tokens.len() as f64) / self.avg_doc_len);
                        score += idf * numerator / denominator;
                    }
                }
                (i, score)
            })
            .collect();

        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scores
            .into_iter()
            .filter(|(_, score)| *score > 0.0)
            .take(k)
            .map(|(i, _)| i)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_search() {
        let docs = vec![
            "This document discusses SQL injection vulnerabilities",
            "Cross-site scripting attacks involve malicious JavaScript",
            "Buffer overflow occurs when writing beyond allocated memory",
        ];

        let index = Bm25Index::new(docs, 1.2, 0.75);
        let results = index.search("sql injection", 3);

        assert!(!results.is_empty());
        assert_eq!(results[0], 0, "SQL injection doc should be ranked first");
    }

    #[test]
    fn test_empty_query() {
        let docs = vec!["test document"];
        let index = Bm25Index::new(docs, 1.2, 0.75);
        let results = index.search("", 3);
        assert!(results.is_empty());
    }

    #[test]
    fn test_single_doc_match() {
        let docs = vec!["SQL injection is a security vulnerability"];
        let index = Bm25Index::new(docs, 1.2, 0.75);
        let results = index.search("sql injection", 1);
        assert_eq!(results, vec![0]);
    }

    #[test]
    fn test_tokenization() {
        let docs = vec!["Hello, World! This is a test."];
        let index = Bm25Index::new(docs, 1.2, 0.75);
        assert_eq!(index.docs[0].tokens.len(), 6);
        assert!(index.docs[0].term_freqs.contains_key("hello"));
        assert!(index.docs[0].term_freqs.contains_key("world"));
    }

    #[test]
    fn test_no_matches() {
        let docs = vec!["completely unrelated content"];
        let index = Bm25Index::new(docs, 1.2, 0.75);
        let results = index.search("xyz123abc", 3);
        assert!(results.is_empty());
    }
}
