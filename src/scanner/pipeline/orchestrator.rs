//! Phase orchestration with data-driven execution.
//!
//! Provides a data-driven PhaseGraph that defines phase execution order,
//! dependencies, and configuration without hard-coded match statements.

use crate::checkpoint::ScanPhase;

use std::collections::HashMap;

/// Metadata for a phase.
#[derive(Debug, Clone)]
pub struct PhaseMetadata {
    pub display_name: String,
    pub description: String,
    pub phase_number: u8,
    pub total_phases: u8,
}

#[derive(Debug, Clone)]
pub struct PhaseGraph {
    phases: Vec<ScanPhase>,
    metadata: HashMap<ScanPhase, PhaseMetadata>,
}

impl PhaseGraph {
    /// Create the default phase graph with all scan phases in execution order.
    pub fn new() -> Self {
        use crate::scanner::phase_spec::PhaseSpec;

        let phases: Vec<ScanPhase> = PhaseSpec::all().to_vec();
        let total = phases.len() as u8;
        let mut metadata = HashMap::new();

        // Build metadata from PhaseSpec slots
        for (index, slot) in PhaseSpec::slots().iter().enumerate() {
            let phase_number = (index + 1) as u8;
            let display_name = match slot.phase {
                ScanPhase::Indexing => "Indexing",
                ScanPhase::Semgrep => "Semgrep",
                ScanPhase::CpgSlice => "CPG Slice",
                ScanPhase::LlmStaticAnalysis => "LLM Static Analysis",
                ScanPhase::CweRouting => "CWE Routing",
                ScanPhase::RuleSynthesis => "Rule Synthesis",
                ScanPhase::LlmDiscovery => "LLM Discovery",
                ScanPhase::LlmVerification => "LLM Verification",
                ScanPhase::Validate => "Validate",
                ScanPhase::SecurityAgentVerification => "SecurityAgent Verification",
                ScanPhase::TicketCrossRef => "Ticket Cross-Reference",
                ScanPhase::GitAnalysis => "Git Analysis",
                ScanPhase::CrossFileAnalysis => "Cross-File Analysis",
                ScanPhase::ConfidenceScoring => "Confidence Scoring",
                ScanPhase::AiAggregation => "AI Aggregation",
                ScanPhase::ThreatModeling => "Threat Modeling",
                ScanPhase::RootCauseDedup => "Root Cause Deduplication",
                ScanPhase::MultiVerifier => "Multi-Verifier",
                ScanPhase::AutoPatching => "Auto-Patching",
                ScanPhase::CveBootstrap => "CVE Bootstrap",
                ScanPhase::PocCompiler => "PoC Compiler",
                ScanPhase::ExploitSynth => "Exploit Synthesis",
                ScanPhase::VariantSearch => "Variant Search",
                ScanPhase::Reporting => "Reporting",
                ScanPhase::Complete => "Complete",
                ScanPhase::Error => "Error",
            };

            let description = match slot.phase {
                ScanPhase::Indexing => "Index project files",
                ScanPhase::Semgrep => "Run Semgrep static analysis",
                ScanPhase::CpgSlice => "Code Property Graph slicing (Joern)",
                ScanPhase::LlmStaticAnalysis => "Analyze files with LLM",
                ScanPhase::CweRouting => "Route findings to specialized models",
                ScanPhase::RuleSynthesis => "LLM-generated Semgrep rules (MoCQ)",
                ScanPhase::LlmDiscovery => "Enrich findings with AI context",
                ScanPhase::LlmVerification => "Verify findings with AI",
                ScanPhase::Validate => {
                    "LLM-as-judge rationale check (CORRECT paper arxiv:2504.13474)"
                }
                ScanPhase::SecurityAgentVerification => "Tool-based verification",
                ScanPhase::TicketCrossRef => "Cross-reference with ticket systems",
                ScanPhase::GitAnalysis => "Analyze Git history",
                ScanPhase::CrossFileAnalysis => "Analyze cross-file references",
                ScanPhase::ConfidenceScoring => "Refine confidence scores",
                ScanPhase::AiAggregation => "Aggregate findings with AI",
                ScanPhase::ThreatModeling => "Generate threat model",
                ScanPhase::RootCauseDedup => "Deduplicate by root cause",
                ScanPhase::MultiVerifier => "Verify with multiple agents",
                ScanPhase::AutoPatching => "Generate patches automatically",
                ScanPhase::CveBootstrap => "Enrich with CVE data",
                ScanPhase::PocCompiler => "Compile and validate PoCs",
                ScanPhase::ExploitSynth => "Sandbox-verified exploit generation",
                ScanPhase::VariantSearch => "Search for code variants",
                ScanPhase::Reporting => "Generate reports",
                ScanPhase::Complete => "Scan complete",
                ScanPhase::Error => "Error occurred",
            };

            metadata.insert(
                slot.phase.clone(),
                PhaseMetadata {
                    display_name: display_name.to_string(),
                    description: description.to_string(),
                    phase_number,
                    total_phases: total,
                },
            );
        }

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

    /// Total number of phases in the scan pipeline (24).
    pub fn total_phases(&self) -> usize {
        self.phases.len()
    }

    /// Get the 1-based index of a phase in the pipeline.
    pub fn phase_index(&self, phase: &ScanPhase) -> usize {
        self.phases.iter().position(|p| p == phase).unwrap_or(0) + 1
    }

    /// Get the display name for a phase in "NN/24 Name" format.
    pub fn display_name(&self, phase: &ScanPhase) -> String {
        if let Some(metadata) = self.metadata.get(phase) {
            format!(
                "{}/{} {}",
                metadata.phase_number, metadata.total_phases, metadata.display_name
            )
        } else {
            // Fallback for phases not in the graph
            "?/? Unknown".to_string()
        }
    }
}

/// Standalone helper: total phases in the default pipeline.
pub fn total_phases() -> usize {
    PhaseGraph::new().total_phases()
}

/// Standalone helper: get 1-based phase index.
pub fn phase_index(phase: &ScanPhase) -> usize {
    PhaseGraph::new().phase_index(phase)
}

impl Default for PhaseGraph {
    fn default() -> Self {
        Self::new()
    }
}
