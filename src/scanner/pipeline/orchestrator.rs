//! Phase orchestration with data-driven execution.
//!
//! Provides a data-driven PhaseGraph that defines phase execution order,
//! dependencies, and configuration without hard-coded match statements.

use crate::checkpoint::ScanPhase;
use crate::config;

use std::collections::HashMap;

/// Metadata for a phase.
#[derive(Debug, Clone)]
pub struct PhaseMetadata {
    pub display_name: String,
    pub description: String,
    pub phase_number: u8,
    pub total_phases: u8,
}

/// Data-driven phase graph defining scan execution order.
#[derive(Debug, Clone)]
pub struct PhaseGraph {
    phases: Vec<ScanPhase>,
    metadata: HashMap<ScanPhase, PhaseMetadata>,
}

impl PhaseGraph {
    /// Create the default phase graph with all scan phases in execution order.
    ///
    /// The 20-phase pipeline mirrors the real orchestrator in
    /// `src/scanner/orchestrator.rs`: Reporting runs last so that any
    /// modifications made by earlier phases are reflected in the output.
    pub fn new() -> Self {
        let phases = vec![
            ScanPhase::Indexing,
            ScanPhase::Semgrep,
            ScanPhase::CweRouting,
            ScanPhase::LlmStaticAnalysis,
            ScanPhase::LlmDiscovery,
            ScanPhase::LlmVerification,
            ScanPhase::SecurityAgentVerification,
            ScanPhase::TicketCrossRef,
            ScanPhase::GitAnalysis,
            ScanPhase::CrossFileAnalysis,
            ScanPhase::ConfidenceScoring,
            ScanPhase::AiAggregation,
            ScanPhase::ThreatModeling,
            ScanPhase::RootCauseDedup,
            ScanPhase::MultiVerifier,
            ScanPhase::AutoPatching,
            ScanPhase::CveBootstrap,
            ScanPhase::PocCompiler,
            ScanPhase::VariantSearch,
            ScanPhase::Reporting,
        ];

        let total = phases.len() as u8;
        let mut metadata = HashMap::new();

        macro_rules! add_metadata {
            ($phase:expr, $name:expr, $desc:expr, $num:expr) => {
                metadata.insert(
                    $phase.clone(),
                    PhaseMetadata {
                        display_name: $name.to_string(),
                        description: $desc.to_string(),
                        phase_number: $num,
                        total_phases: total,
                    },
                );
            };
        }

        add_metadata!(ScanPhase::Indexing, "Indexing", "Index project files", 1);
        add_metadata!(
            ScanPhase::Semgrep,
            "Semgrep",
            "Run Semgrep static analysis",
            2
        );
        add_metadata!(
            ScanPhase::CweRouting,
            "CWE Routing",
            "Route findings to specialized models",
            3
        );
        add_metadata!(
            ScanPhase::LlmStaticAnalysis,
            "LLM Static Analysis",
            "Analyze files with LLM",
            4
        );
        add_metadata!(
            ScanPhase::LlmDiscovery,
            "LLM Discovery",
            "Enrich findings with AI context",
            5
        );
        add_metadata!(
            ScanPhase::LlmVerification,
            "LLM Verification",
            "Verify findings with AI",
            6
        );
        add_metadata!(
            ScanPhase::SecurityAgentVerification,
            "SecurityAgent Verification",
            "Tool-based verification",
            7
        );
        add_metadata!(
            ScanPhase::TicketCrossRef,
            "Ticket Cross-Reference",
            "Cross-reference with ticket systems",
            8
        );
        add_metadata!(
            ScanPhase::GitAnalysis,
            "Git Analysis",
            "Analyze Git history",
            9
        );
        add_metadata!(
            ScanPhase::CrossFileAnalysis,
            "Cross-File Analysis",
            "Analyze cross-file references",
            10
        );
        add_metadata!(
            ScanPhase::ConfidenceScoring,
            "Confidence Scoring",
            "Refine confidence scores",
            11
        );
        add_metadata!(
            ScanPhase::AiAggregation,
            "AI Aggregation",
            "Aggregate findings with AI",
            12
        );
        add_metadata!(
            ScanPhase::ThreatModeling,
            "Threat Modeling",
            "Generate threat model",
            13
        );
        add_metadata!(
            ScanPhase::RootCauseDedup,
            "Root Cause Deduplication",
            "Deduplicate by root cause",
            14
        );
        add_metadata!(
            ScanPhase::MultiVerifier,
            "Multi-Verifier",
            "Verify with multiple agents",
            15
        );
        add_metadata!(
            ScanPhase::AutoPatching,
            "Auto-Patching",
            "Generate patches automatically",
            16
        );
        add_metadata!(
            ScanPhase::CveBootstrap,
            "CVE Bootstrap",
            "Enrich with CVE data",
            17
        );
        add_metadata!(
            ScanPhase::PocCompiler,
            "PoC Compiler",
            "Compile and validate PoCs",
            18
        );
        add_metadata!(
            ScanPhase::VariantSearch,
            "Variant Search",
            "Search for code variants",
            19
        );
        add_metadata!(ScanPhase::Reporting, "Reporting", "Generate reports", 20);

        Self { phases, metadata }
    }

    /// Get all phases in execution order.
    pub fn phases(&self) -> &[ScanPhase] {
        &self.phases
    }

    /// Get metadata for a phase.
    pub fn get_metadata(&self, phase: &ScanPhase) -> Option<&PhaseMetadata> {
        self.metadata.get(phase)
    }

    /// Get the next phase after the given phase.
    pub fn next_phase(&self, current: &ScanPhase) -> Option<&ScanPhase> {
        let idx = self.phases.iter().position(|p| p == current)?;
        if idx + 1 < self.phases.len() {
            Some(&self.phases[idx + 1])
        } else {
            None
        }
    }

    /// Get the previous phase before the given phase.
    pub fn previous_phase(&self, current: &ScanPhase) -> Option<&ScanPhase> {
        let idx = self.phases.iter().position(|p| p == current)?;
        if idx > 0 {
            Some(&self.phases[idx - 1])
        } else {
            None
        }
    }
}

impl Default for PhaseGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Orchestrates phase execution with checkpointing support.
pub struct Orchestrator<'a> {
    phase_graph: PhaseGraph,
    config: &'a config::ScannerConfig,
}

impl<'a> Orchestrator<'a> {
    /// Create a new orchestrator with the given config.
    pub fn new(config: &'a config::ScannerConfig) -> Self {
        Self {
            phase_graph: PhaseGraph::new(),
            config,
        }
    }

    /// Get the phase graph.
    pub fn phase_graph(&self) -> &PhaseGraph {
        &self.phase_graph
    }

    /// Get the config reference.
    pub fn config(&self) -> &'a config::ScannerConfig {
        self.config
    }
}
