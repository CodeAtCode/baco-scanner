//! VulInSpec: Specification-guided vulnerability detection.
//!
//! This module implements the VulInSpec approach (arXiv:2511.04014) which:
//! 1. Extracts security specifications from historical vulnerabilities/patches
//! 2. Builds a specification knowledge base with general and domain-specific specs
//! 3. Uses RAG retrieval to find relevant past cases and specifications
//! 4. Enhances LLM discovery phase to reason about expected safe behaviors
//!
//! All features are disabled by default and must be explicitly enabled via config.

pub mod extractor;
pub mod retriever;
pub mod schema;

// Re-export main types for convenience
pub use schema::{DomainCategory, SecuritySpecification, SpecificationSource, VulnSpecConfig};
