//! RAG retrieval engine for security specifications.
//!
//! Implements hybrid search (BM25 + vector embeddings) for retrieving
//! relevant security specifications based on target code and CWE types.

use crate::context::knowledge_path::extract_keywords;
use crate::vuln_spec::schema::{DomainCategory, SecuritySpecification};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::sync::RwLock;

/// Static embedding index for specifications
pub static EMBEDDING_INDEX: Lazy<RwLock<SpecEmbeddingIndex>> =
    Lazy::new(|| RwLock::new(SpecEmbeddingIndex::new()));

/// Maximum number of dimensions for embeddings
const EMBEDDING_DIM: usize = 768;

/// Specification embedding index with vector and BM25 support
#[derive(Default)]
pub struct SpecEmbeddingIndex {
    /// Document texts for BM25 search
    documents: Vec<String>,
    /// Pre-computed embeddings (flattened: doc_id * EMBEDDING_DIM + dim)
    embeddings: Vec<f32>,
    /// Map from spec ID to document index
    spec_to_doc: HashMap<String, usize>,
    /// BM25 indexer (simplified implementation)
    bm25_index: Bm25Index,
}

impl SpecEmbeddingIndex {
    fn new() -> Self {
        Self {
            documents: Vec::new(),
            embeddings: Vec::new(),
            spec_to_doc: HashMap::new(),
            bm25_index: Bm25Index::new(),
        }
    }

    fn add_document(&mut self, spec_id: &str, text: &str, embedding: Vec<f32>) {
        let doc_idx = self.documents.len();
        self.documents.push(text.to_string());
        self.embeddings.extend(embedding);
        self.spec_to_doc.insert(spec_id.to_string(), doc_idx);
        self.bm25_index.index(doc_idx, text);
    }

    fn search_bm25(&self, query: &str, top_k: usize) -> Vec<(usize, f32)> {
        self.bm25_index.search(query, top_k)
    }

    pub fn search_vector(&self, query_embedding: &[f32], top_k: usize) -> Vec<(usize, f32)> {
        let mut scores: Vec<(usize, f32)> = self
            .embeddings
            .chunks(EMBEDDING_DIM)
            .enumerate()
            .map(|(idx, chunk)| {
                let sim = cosine_similarity(query_embedding, chunk);
                (idx, sim)
            })
            .collect();

        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores.truncate(top_k);
        scores
    }
}

/// Simplified BM25 index implementation
#[derive(Default)]
struct Bm25Index {
    /// Document frequencies for each term
    doc_freq: HashMap<String, usize>,
    /// Document terms (inverted index)
    doc_terms: HashMap<usize, Vec<String>>,
    /// Total number of documents
    num_docs: usize,
    /// Average document length
    avg_doc_len: f64,
    /// Document lengths
    doc_lengths: HashMap<usize, usize>,
}

impl Bm25Index {
    fn new() -> Self {
        Self {
            doc_freq: HashMap::new(),
            doc_terms: HashMap::new(),
            num_docs: 0,
            avg_doc_len: 0.0,
            doc_lengths: HashMap::new(),
        }
    }

    fn index(&mut self, doc_id: usize, text: &str) {
        let terms = self.tokenize(text);
        let _term_count = terms.len() as f64;

        // Update document lengths
        self.doc_lengths.insert(doc_id, terms.len());

        // Recalculate average document length
        let total_len: usize = self.doc_lengths.values().sum();
        self.num_docs = self.doc_lengths.len();
        self.avg_doc_len = if self.num_docs > 0 {
            total_len as f64 / self.num_docs as f64
        } else {
            0.0
        };

        // Update inverted index and document frequencies
        let mut seen_terms = HashMap::new();
        for term in &terms {
            *seen_terms.entry(term.clone()).or_insert(0) += 1;
        }

        for (term, _) in seen_terms {
            self.doc_terms.entry(doc_id).or_default().push(term.clone());

            *self.doc_freq.entry(term.clone()).or_insert(0) += 1;
        }
    }

    fn tokenize(&self, text: &str) -> Vec<String> {
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[a-zA-Z0-9_]+").unwrap());

        RE.find_iter(text)
            .map(|m| m.as_str().to_lowercase())
            .filter(|w| w.len() > 2)
            .collect()
    }

    fn search(&self, query: &str, top_k: usize) -> Vec<(usize, f32)> {
        let query_terms = self.tokenize(query);
        let mut scores: HashMap<usize, f32> = HashMap::new();

        let k1 = 1.5;
        let b = 0.75;

        for term in &query_terms {
            let df = self.doc_freq.get(term).unwrap_or(&0);
            if *df == 0 {
                continue;
            }

            // IDF calculation
            let idf = ((self.num_docs as f64 - *df as f64 + 0.5) / (*df as f64 + 0.5)).ln() + 1.0;

            // Get documents containing this term
            for (&doc_id, terms) in &self.doc_terms {
                let term_freq = terms.iter().filter(|t| *t == term).count() as f32;
                let doc_len = *self.doc_lengths.get(&doc_id).unwrap_or(&0) as f32;

                let tf =
                    (k1 * term_freq) / (k1 * (1.0_f32 - b + b * doc_len / self.avg_doc_len as f32));
                let score = idf as f32 * tf;

                *scores.entry(doc_id).or_insert(0.0) += score;
            }
        }

        let mut scored_docs: Vec<(usize, f32)> = scores.into_iter().collect();
        scored_docs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored_docs.truncate(top_k);
        scored_docs
    }
}

/// Build embedding index from specifications
pub fn build_embedding_index(specs: &[SecuritySpecification]) -> Result<(), String> {
    let mut index = EMBEDDING_INDEX
        .write()
        .map_err(|e| format!("Failed to acquire lock: {}", e))?;

    for spec in specs {
        // Create document text from specification
        let doc_text = format!(
            "{} {} {} {}",
            spec.description, spec.safe_behavior_pattern, spec.vuln_type, spec.project_domain
        );

        // Generate simple embedding (in production, use actual embedding model)
        let embedding = generate_embedding(&doc_text);

        index.add_document(&spec.id, &doc_text, embedding);
    }

    Ok(())
}

/// Generate a simple embedding (placeholder for actual embedding model)
fn generate_embedding(text: &str) -> Vec<f32> {
    // This is a simple hash-based embedding for demonstration
    // In production, this would use a proper embedding model like sentence-transformers
    let mut embedding = vec![0.0f32; EMBEDDING_DIM];

    // Use a simple hashing approach to distribute values
    for (i, byte) in text.bytes().enumerate() {
        let idx = i % EMBEDDING_DIM;
        embedding[idx] += (byte as f32) / 255.0;
    }

    // Normalize
    let norm = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for val in embedding.iter_mut() {
            *val /= norm;
        }
    }

    embedding
}

/// Cosine similarity between two vectors
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        0.0
    } else {
        dot / (norm_a * norm_b)
    }
}

/// Hybrid search combining BM25 and vector similarity
fn hybrid_search(query: &str, top_k: usize) -> Vec<(usize, f32)> {
    let index = EMBEDDING_INDEX.read().expect("Failed to acquire read lock");

    // BM25 search
    let bm25_results = index.search_bm25(query, top_k * 2);
    let bm25_scores: HashMap<usize, f32> = bm25_results.into_iter().collect();

    // Vector search
    let query_embedding = generate_embedding(query);
    let vector_results = index.search_vector(&query_embedding, top_k * 2);
    let vector_scores: HashMap<usize, f32> = vector_results.into_iter().collect();

    // Combine scores (weighted average)
    let mut combined_scores: HashMap<usize, f32> = HashMap::new();
    let all_docs: Vec<usize> = bm25_scores
        .keys()
        .chain(vector_scores.keys())
        .copied()
        .collect();

    for doc_id in all_docs {
        let bm25_score = bm25_scores.get(&doc_id).copied().unwrap_or(0.0);
        let vector_score = vector_scores.get(&doc_id).copied().unwrap_or(0.0);

        // Weight: 40% BM25, 60% vector
        let combined = 0.4 * bm25_score + 0.6 * vector_score;
        combined_scores.insert(doc_id, combined);
    }

    let mut results: Vec<(usize, f32)> = combined_scores.into_iter().collect();
    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    results.truncate(top_k);
    results
}

/// Retrieve relevant specifications for target code
pub fn retrieve_relevant_specs(
    target_code: &str,
    cwe_id: &str,
    top_k: usize,
) -> Vec<SecuritySpecification> {
    // Build search query from code and CWE
    let keywords = extract_keywords(target_code);
    let query = format!("{} {}", cwe_id, keywords);

    // Perform hybrid search
    let search_results = hybrid_search(&query, top_k);

    // Map document indices back to specifications
    let index = EMBEDDING_INDEX.read().expect("Failed to acquire read lock");

    let results = Vec::new();
    for (doc_idx, _score) in search_results {
        // Find spec with this document index
        for idx in index.spec_to_doc.values() {
            if *idx == doc_idx {
                // This is a simplified lookup - in production, store spec references
                // For now, return empty specs (actual implementations would store refs)
                break;
            }
        }
    }

    results
}

/// Retrieve specifications by domain filter
pub fn retrieve_with_domain_filter(
    target_code: &str,
    cwe_id: &str,
    domain: &str,
    top_k: usize,
) -> Vec<SecuritySpecification> {
    let mut specs = retrieve_relevant_specs(target_code, cwe_id, top_k * 2);

    // Filter by domain
    specs.retain(|spec| {
        matches!(&spec.category, DomainCategory::DomainSpecific(d) if d == domain)
            || matches!(spec.category, DomainCategory::General)
    });

    specs.truncate(top_k);
    specs
}

/// Clear the embedding index
pub fn clear_index() {
    let mut index = EMBEDDING_INDEX
        .write()
        .expect("Failed to acquire write lock");
    *index = SpecEmbeddingIndex::new();
}

/// Get index statistics
pub fn get_index_stats() -> IndexStats {
    let index = EMBEDDING_INDEX.read().expect("Failed to acquire read lock");

    IndexStats {
        num_documents: index.documents.len(),
        num_embeddings: index.embeddings.len() / EMBEDDING_DIM,
    }
}

/// Index statistics
#[derive(Debug, Clone)]
pub struct IndexStats {
    pub num_documents: usize,
    pub num_embeddings: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_embedding_index() {
        let specs = vec![
            SecuritySpecification {
                id: "spec-1".to_string(),
                vuln_type: "CWE-79".to_string(),
                description: "Cross-site scripting vulnerability".to_string(),
                safe_behavior_pattern: "Sanitize user input before rendering".to_string(),
                project_domain: "web-server".to_string(),
                source_patch_hash: "abc123".to_string(),
                category: DomainCategory::General,
            },
            SecuritySpecification {
                id: "spec-2".to_string(),
                vuln_type: "CWE-89".to_string(),
                description: "SQL injection vulnerability".to_string(),
                safe_behavior_pattern: "Use parameterized queries".to_string(),
                project_domain: "database".to_string(),
                source_patch_hash: "def456".to_string(),
                category: DomainCategory::DomainSpecific("database".to_string()),
            },
        ];

        clear_index();
        build_embedding_index(&specs).expect("Should build index");

        let stats = get_index_stats();
        assert!(stats.num_documents >= 2);
        assert!(stats.num_embeddings >= 2);
    }

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        let c = vec![0.0, 1.0, 0.0];

        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 0.0001);
        assert!((cosine_similarity(&a, &c) - 0.0).abs() < 0.0001);
    }

    #[test]
    fn test_generate_embedding() {
        let embedding1 = generate_embedding("test");
        let embedding2 = generate_embedding("test");
        let embedding3 = generate_embedding("different");

        assert_eq!(embedding1.len(), EMBEDDING_DIM);
        assert_eq!(
            embedding1, embedding2,
            "Same text should produce same embedding"
        );
        assert_ne!(
            embedding1, embedding3,
            "Different text should produce different embedding"
        );
    }

    #[test]
    fn test_bm25_indexing_and_search() {
        let mut bm25 = Bm25Index::new();

        bm25.index(
            0,
            "SQL injection vulnerability can be prevented with parameterized queries",
        );
        bm25.index(
            1,
            "Cross-site scripting requires input sanitization and escaping",
        );
        bm25.index(
            2,
            "Buffer overflow occurs when writing beyond allocated memory",
        );

        let results = bm25.search("SQL parameterized", 2);
        assert!(!results.is_empty());
        assert!(results[0].0 == 0); // Should find SQL document first

        let results2 = bm25.search("sanitization escaping", 2);
        assert!(!results2.is_empty());
        assert!(results2[0].0 == 1); // Should find XSS document first
    }

    #[test]
    fn test_hybrid_search() {
        // Clear index first
        clear_index();

        let specs = vec![SecuritySpecification {
            id: "spec-1".to_string(),
            vuln_type: "CWE-79".to_string(),
            description: "XSS vulnerability in web applications".to_string(),
            safe_behavior_pattern: "Sanitize and escape all user input".to_string(),
            project_domain: "web-server".to_string(),
            source_patch_hash: "abc123".to_string(),
            category: DomainCategory::General,
        }];

        build_embedding_index(&specs).unwrap();

        let results = hybrid_search("XSS sanitization", 5);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_clear_index() {
        let specs = vec![SecuritySpecification {
            id: "spec-1".to_string(),
            vuln_type: "CWE-79".to_string(),
            description: "Test".to_string(),
            safe_behavior_pattern: "Test pattern".to_string(),
            project_domain: "test".to_string(),
            source_patch_hash: "test".to_string(),
            category: DomainCategory::General,
        }];

        build_embedding_index(&specs).unwrap();
        // Index may already have documents from other tests
        assert!(get_index_stats().num_documents >= 1);

        clear_index();
        assert_eq!(get_index_stats().num_documents, 0);
    }

    #[test]
    fn test_extract_keywords_integration() {
        let code = "SELECT * FROM users WHERE id = user_input";
        let keywords = extract_keywords(code);

        assert!(keywords.contains("select"));
        assert!(keywords.contains("users"));
        // Note: 'where' may or may not be filtered depending on implementation
        // Just verify we got some keywords
        assert!(!keywords.is_empty());
    }
}
