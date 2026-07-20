//! CWE Knowledge Base with BM25 retrieval for security vulnerability specifications.
//!
//! This module provides retrieval-augmented generation (RAG) capabilities by indexing
//! CWE specifications and enabling semantic search over vulnerability descriptions.

mod bm25;

use serde::{Deserialize, Serialize};

pub use bm25::Bm25Index;

/// A CWE specification document with vulnerability details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweDocument {
    pub cwe_id: String,
    pub name: String,
    pub description: String,
    pub examples: Vec<String>,
    pub mitigation: String,
}

/// Error types for retrieval operations
#[derive(Debug, Clone)]
pub enum RetrievalError {
    JsonError(String),
    Empty,
}

impl std::fmt::Display for RetrievalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RetrievalError::JsonError(e) => write!(f, "JSON error: {}", e),
            RetrievalError::Empty => write!(f, "No documents available"),
        }
    }
}

impl std::error::Error for RetrievalError {}

/// A CWE specification document with search index
#[derive(Debug, Clone)]
pub struct IndexedCweDocument {
    pub document: CweDocument,
    pub search_text: String,
}

/// Knowledge base for CWE specifications with BM25 retrieval
#[derive(Debug)]
pub struct CweKnowledgeBase {
    documents: Vec<IndexedCweDocument>,
    index: Bm25Index,
}

impl CweKnowledgeBase {
    /// Load knowledge base from embedded JSON data
    ///
    /// This uses compile-time inclusion of the CWE data for fast startup.
    pub fn load_embedded() -> Result<Self, RetrievalError> {
        let json = include_str!("cwe_data.json");
        Self::load_from_json(json)
    }

    /// Load knowledge base from JSON string
    ///
    /// # Arguments
    /// * `json` - JSON string containing CWE specifications
    ///
    /// # Returns
    /// * `Ok(CweKnowledgeBase)` - Successfully loaded knowledge base
    /// * `Err(RetrievalError)` - JSON parsing failed
    pub fn load_from_json(json: &str) -> Result<Self, RetrievalError> {
        #[derive(Deserialize)]
        struct CweData {
            cwe_specifications: Vec<CweDocument>,
        }

        let data: CweData =
            serde_json::from_str(json).map_err(|e| RetrievalError::JsonError(e.to_string()))?;

        if data.cwe_specifications.is_empty() {
            return Err(RetrievalError::Empty);
        }

        let indexed_docs: Vec<IndexedCweDocument> = data
            .cwe_specifications
            .into_iter()
            .map(|doc| {
                let search_text = Self::build_search_text(&doc);
                IndexedCweDocument {
                    document: doc,
                    search_text,
                }
            })
            .collect();

        let search_texts: Vec<&str> = indexed_docs
            .iter()
            .map(|d| d.search_text.as_str())
            .collect();

        let index = Bm25Index::new(search_texts, 1.2, 0.75);

        Ok(CweKnowledgeBase {
            documents: indexed_docs,
            index,
        })
    }

    /// Build searchable text from a CWE document
    fn build_search_text(doc: &CweDocument) -> String {
        let mut text = format!("{} {} {}", doc.cwe_id, doc.name, doc.description);

        for example in &doc.examples {
            text.push(' ');
            text.push_str(example);
        }

        text.push(' ');
        text.push_str(&doc.mitigation);

        text
    }

    /// Search for CWE specifications matching the query
    ///
    /// # Arguments
    /// * `query` - Search query text
    /// * `k` - Maximum number of results to return
    ///
    /// # Returns
    /// Vector of references to matching CWE documents, ranked by relevance
    pub fn search(&self, query: &str, k: usize) -> Vec<&CweDocument> {
        let indices = self.index.search(query, k);
        indices
            .into_iter()
            .filter_map(|i| self.documents.get(i).map(|d| &d.document))
            .collect()
    }

    /// Get the number of documents in the knowledge base
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Check if the knowledge base is empty
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    /// Get all CWE IDs in the knowledge base
    pub fn get_cwe_ids(&self) -> Vec<&str> {
        self.documents
            .iter()
            .map(|d| d.document.cwe_id.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_embedded_success() {
        let kb = CweKnowledgeBase::load_embedded().expect("Failed to load embedded CWE data");
        assert!(!kb.is_empty());
        assert!(kb.len() >= 20, "Should have at least 20 CWE documents");
    }

    #[test]
    fn test_search_sql_injection() {
        let kb = CweKnowledgeBase::load_embedded().unwrap();
        let results = kb.search("sql injection", 3);

        assert!(!results.is_empty(), "Should find results for sql injection");
        assert!(
            results.iter().any(|d| d.cwe_id == "CWE-89"),
            "CWE-89 should be in top results for SQL injection"
        );
    }

    #[test]
    fn test_search_xss() {
        let kb = CweKnowledgeBase::load_embedded().unwrap();
        let results = kb.search("cross site scripting", 1);

        assert!(!results.is_empty(), "Should find results for XSS");
        assert_eq!(
            results[0].cwe_id, "CWE-79",
            "CWE-79 should be top result for cross-site scripting"
        );
    }

    #[test]
    fn test_search_empty_query() {
        let kb = CweKnowledgeBase::load_embedded().unwrap();
        let results = kb.search("", 10);
        assert!(results.is_empty(), "Empty query should return no results");
    }

    #[test]
    fn test_load_malformed_json() {
        let result = CweKnowledgeBase::load_from_json("{ invalid json }");
        assert!(result.is_err(), "Should fail on malformed JSON");
        match result {
            Err(RetrievalError::JsonError(_)) => (),
            _ => panic!("Should return JsonError variant"),
        }
    }

    #[test]
    fn test_get_cwe_ids() {
        let kb = CweKnowledgeBase::load_embedded().unwrap();
        let ids = kb.get_cwe_ids();
        assert!(ids.contains(&"CWE-79"));
        assert!(ids.contains(&"CWE-89"));
        assert!(ids.contains(&"CWE-22"));
    }
}
