//! Phase orchestration with data-driven execution.
//!
//! Provides a data-driven PhaseGraph that defines phase execution order,
//! dependencies, and configuration without hard-coded match statements.

use crate::checkpoint::ScanPhase;
use crate::config;

use std::collections::HashMap;

/// Defines the phase execution graph.
///
/// Data-driven definition of scan phases with their execution order,
/// dependencies, and enable/disable logic.
pub struct PhaseGraph {
    /// Ordered list of phases to execute.
    phases: Vec<ScanPhase>,
    /// Phase metadata (display names, descriptions).
    metadata: HashMap<ScanPhase, PhaseMetadata>,
}

/// Metadata for a phase.
#[derive(Debug, Clone)]
pub struct PhaseMetadata {
    pub display_name: String,
    pub description: String,
    pub phase_number: u8,
    pub total_phases: u8,
}

impl PhaseGraph {
    /// Create the default phase graph with all scan phases.
    pub fn new() -> Self {
        let phases = vec![
            ScanPhase::Indexing,
            ScanPhase::Semgrep,
            ScanPhase::LlmStaticAnalysis,
            ScanPhase::LlmDiscovery,
            ScanPhase::LlmVerification,
            ScanPhase::SecurityAgentVerification,
            ScanPhase::TicketCrossRef,
            ScanPhase::GitAnalysis,
            ScanPhase::CrossFileAnalysis,
            ScanPhase::ConfidenceScoring,
            ScanPhase::AiAggregation,
            ScanPhase::Reporting,
            ScanPhase::ThreatModeling,
            ScanPhase::RootCauseDedup,
            ScanPhase::MultiVerifier,
            ScanPhase::AutoPatching,
            ScanPhase::CveBootstrap,
            ScanPhase::PocCompiler,
            ScanPhase::VariantSearch,
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
            ScanPhase::LlmStaticAnalysis,
            "LLM Static Analysis",
            "Analyze files with LLM",
            3
        );
        add_metadata!(
            ScanPhase::LlmDiscovery,
            "LLM Discovery",
            "Enrich findings with AI context",
            4
        );
        add_metadata!(
            ScanPhase::LlmVerification,
            "LLM Verification",
            "Verify findings with AI",
            5
        );
        add_metadata!(
            ScanPhase::SecurityAgentVerification,
            "SecurityAgent Verification",
            "Tool-based verification",
            6
        );
        add_metadata!(
            ScanPhase::TicketCrossRef,
            "Ticket Cross-Reference",
            "Cross-reference with ticket systems",
            7
        );
        add_metadata!(
            ScanPhase::GitAnalysis,
            "Git Analysis",
            "Analyze Git history",
            8
        );
        add_metadata!(
            ScanPhase::CrossFileAnalysis,
            "Cross-File Analysis",
            "Analyze cross-file references",
            9
        );
        add_metadata!(
            ScanPhase::ConfidenceScoring,
            "Confidence Scoring",
            "Refine confidence scores",
            10
        );
        add_metadata!(
            ScanPhase::AiAggregation,
            "AI Aggregation",
            "Aggregate findings with AI",
            11
        );
        add_metadata!(ScanPhase::Reporting, "Reporting", "Generate reports", 12);
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

    /// Check if a phase is enabled based on config.
    pub fn is_phase_enabled(&self, phase: &ScanPhase, config: &config::ScannerConfig) -> bool {
        use ScanPhase::*;
        match phase {
            ConfidenceScoring => config.scanner.performance.enable_confidence_refinement,
            ThreatModeling => config.scanner.performance.enable_threat_modeling,
            RootCauseDedup => config.scanner.performance.enable_root_cause_dedup,
            MultiVerifier => config.scanner.performance.enable_multi_verifier,
            AutoPatching => config.scanner.performance.enable_auto_patching,
            CveBootstrap => config.scanner.performance.enable_cve_bootstrap,
            PocCompiler => config.scanner.performance.enable_poc_compilation,
            VariantSearch => config.scanner.performance.enable_variant_search,
            _ => true,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // PhaseGraph Construction Tests
    // ============================================================================

    #[test]
    fn test_phase_graph_new_correct_order() {
        let graph = PhaseGraph::new();
        let phases = graph.phases();

        // Verify the correct number of phases
        assert_eq!(phases.len(), 19);

        // Verify the first phase is Indexing
        assert_eq!(phases[0], ScanPhase::Indexing);

        // Verify the last phase is VariantSearch
        assert_eq!(phases[18], ScanPhase::VariantSearch);

        // Verify key phase ordering
        assert_eq!(phases[1], ScanPhase::Semgrep);
        assert_eq!(phases[2], ScanPhase::LlmStaticAnalysis);
        assert_eq!(phases[17], ScanPhase::PocCompiler);
    }

    #[test]
    fn test_phase_graph_all_phases_present() {
        let graph = PhaseGraph::new();
        let phases = graph.phases();

        let expected_phases = vec![
            ScanPhase::Indexing,
            ScanPhase::Semgrep,
            ScanPhase::LlmStaticAnalysis,
            ScanPhase::LlmDiscovery,
            ScanPhase::LlmVerification,
            ScanPhase::SecurityAgentVerification,
            ScanPhase::TicketCrossRef,
            ScanPhase::GitAnalysis,
            ScanPhase::CrossFileAnalysis,
            ScanPhase::ConfidenceScoring,
            ScanPhase::AiAggregation,
            ScanPhase::Reporting,
            ScanPhase::ThreatModeling,
            ScanPhase::RootCauseDedup,
            ScanPhase::MultiVerifier,
            ScanPhase::AutoPatching,
            ScanPhase::CveBootstrap,
            ScanPhase::PocCompiler,
            ScanPhase::VariantSearch,
        ];

        for (i, expected) in expected_phases.iter().enumerate() {
            assert_eq!(phases[i], *expected, "Phase mismatch at index {}", i);
        }
    }

    // ============================================================================
    // PhaseMetadata Tests
    // ============================================================================

    #[test]
    fn test_phase_metadata_correctness() {
        let graph = PhaseGraph::new();

        // Test Indexing phase metadata
        let indexing_meta = graph.get_metadata(&ScanPhase::Indexing).unwrap();
        assert_eq!(indexing_meta.display_name, "Indexing");
        assert_eq!(indexing_meta.description, "Index project files");
        assert_eq!(indexing_meta.phase_number, 1);
        assert_eq!(indexing_meta.total_phases, 19);

        // Test Semgrep phase metadata
        let semgrep_meta = graph.get_metadata(&ScanPhase::Semgrep).unwrap();
        assert_eq!(semgrep_meta.display_name, "Semgrep");
        assert_eq!(semgrep_meta.description, "Run Semgrep static analysis");
        assert_eq!(semgrep_meta.phase_number, 2);

        // Test final phase metadata
        let variant_meta = graph.get_metadata(&ScanPhase::VariantSearch).unwrap();
        assert_eq!(variant_meta.display_name, "Variant Search");
        assert_eq!(variant_meta.description, "Search for code variants");
        assert_eq!(variant_meta.phase_number, 19);
        assert_eq!(variant_meta.total_phases, 19);
    }

    #[test]
    fn test_phase_metadata_total_phases_consistency() {
        let graph = PhaseGraph::new();

        // All phases should have the same total_phases value
        let expected_total = 19;

        for phase in graph.phases() {
            let meta = graph.get_metadata(phase).unwrap();
            assert_eq!(
                meta.total_phases, expected_total,
                "total_phases mismatch for {:?}",
                phase
            );
        }
    }

    #[test]
    fn test_phase_metadata_phase_number_sequence() {
        let graph = PhaseGraph::new();

        // Verify phase numbers are sequential starting from 1
        for (i, phase) in graph.phases().iter().enumerate() {
            let meta = graph.get_metadata(phase).unwrap();
            assert_eq!(
                meta.phase_number,
                (i + 1) as u8,
                "Phase number mismatch for {:?}: expected {}, got {}",
                phase,
                i + 1,
                meta.phase_number
            );
        }
    }

    // ============================================================================
    // Default Implementation Tests
    // ============================================================================

    #[test]
    fn test_default_implementation() {
        let default_graph = PhaseGraph::default();
        let new_graph = PhaseGraph::new();

        // Default should be equivalent to new()
        assert_eq!(default_graph.phases().len(), new_graph.phases().len());

        // Verify phases are in the same order
        for (default_phase, new_phase) in
            default_graph.phases().iter().zip(new_graph.phases().iter())
        {
            assert_eq!(default_phase, new_phase);
        }
    }

    // ============================================================================
    // Phase Navigation Tests
    // ============================================================================

    #[test]
    fn test_next_phase() {
        let graph = PhaseGraph::new();

        // Test next phase for early phases
        assert_eq!(
            graph.next_phase(&ScanPhase::Indexing),
            Some(&ScanPhase::Semgrep)
        );
        assert_eq!(
            graph.next_phase(&ScanPhase::Semgrep),
            Some(&ScanPhase::LlmStaticAnalysis)
        );

        // Test next phase for middle phases
        assert_eq!(
            graph.next_phase(&ScanPhase::Reporting),
            Some(&ScanPhase::ThreatModeling)
        );

        // Test next phase for last phase (should return None)
        assert_eq!(graph.next_phase(&ScanPhase::VariantSearch), None);

        // Test next phase for non-existent phase (should return None)
        assert_eq!(graph.next_phase(&ScanPhase::Complete), None);
        assert_eq!(graph.next_phase(&ScanPhase::Error), None);
    }

    #[test]
    fn test_previous_phase() {
        let graph = PhaseGraph::new();

        // Test previous phase for early phases (first should return None)
        assert_eq!(graph.previous_phase(&ScanPhase::Indexing), None);
        assert_eq!(
            graph.previous_phase(&ScanPhase::Semgrep),
            Some(&ScanPhase::Indexing)
        );

        // Test previous phase for middle phases
        assert_eq!(
            graph.previous_phase(&ScanPhase::ThreatModeling),
            Some(&ScanPhase::Reporting)
        );

        // Test previous phase for last phase
        assert_eq!(
            graph.previous_phase(&ScanPhase::VariantSearch),
            Some(&ScanPhase::PocCompiler)
        );

        // Test previous phase for non-existent phase (should return None)
        assert_eq!(graph.previous_phase(&ScanPhase::Complete), None);
        assert_eq!(graph.previous_phase(&ScanPhase::Error), None);
    }

    // ============================================================================
    // Phase Enablement Tests
    // ============================================================================

    #[test]
    fn test_is_phase_enabled_default_phases() {
        use crate::config;

        // Create a default config (all advanced features disabled by default)
        let config = config::ScannerConfig::default();

        // Core phases should be enabled by default
        assert!(PhaseGraph::new().is_phase_enabled(&ScanPhase::Indexing, &config));
        assert!(PhaseGraph::new().is_phase_enabled(&ScanPhase::Semgrep, &config));
        assert!(PhaseGraph::new().is_phase_enabled(&ScanPhase::LlmDiscovery, &config));
        assert!(PhaseGraph::new().is_phase_enabled(&ScanPhase::Reporting, &config));
    }

    #[test]
    fn test_is_phase_enabled_advanced_phases() {
        use crate::config;

        // Create a config with all advanced features enabled
        let mut config = config::ScannerConfig::default();
        config.scanner.performance.enable_threat_modeling = true;
        config.scanner.performance.enable_root_cause_dedup = true;
        config.scanner.performance.enable_multi_verifier = true;
        config.scanner.performance.enable_auto_patching = true;
        config.scanner.performance.enable_cve_bootstrap = true;
        config.scanner.performance.enable_poc_compilation = true;
        config.scanner.performance.enable_confidence_refinement = true;
        config.scanner.performance.enable_variant_search = true;

        let graph = PhaseGraph::new();

        // All advanced phases should be enabled
        assert!(graph.is_phase_enabled(&ScanPhase::ThreatModeling, &config));
        assert!(graph.is_phase_enabled(&ScanPhase::RootCauseDedup, &config));
        assert!(graph.is_phase_enabled(&ScanPhase::MultiVerifier, &config));
        assert!(graph.is_phase_enabled(&ScanPhase::AutoPatching, &config));
        assert!(graph.is_phase_enabled(&ScanPhase::CveBootstrap, &config));
        assert!(graph.is_phase_enabled(&ScanPhase::PocCompiler, &config));
        assert!(graph.is_phase_enabled(&ScanPhase::ConfidenceScoring, &config));
        assert!(graph.is_phase_enabled(&ScanPhase::VariantSearch, &config));
    }

    #[test]
    fn test_is_phase_enabled_advanced_phases_disabled() {
        use crate::config;

        // Create a config with all advanced features disabled
        let mut config = config::ScannerConfig::default();
        // Override defaults that are true
        config.scanner.performance.enable_confidence_refinement = false;
        config.scanner.performance.enable_cve_bootstrap = false;
        config.scanner.performance.enable_variant_search = false;

        let graph = PhaseGraph::new();

        // All advanced phases should be disabled
        assert!(!graph.is_phase_enabled(&ScanPhase::ThreatModeling, &config));
        assert!(!graph.is_phase_enabled(&ScanPhase::RootCauseDedup, &config));
        assert!(!graph.is_phase_enabled(&ScanPhase::MultiVerifier, &config));
        assert!(!graph.is_phase_enabled(&ScanPhase::AutoPatching, &config));
        assert!(!graph.is_phase_enabled(&ScanPhase::CveBootstrap, &config));
        assert!(!graph.is_phase_enabled(&ScanPhase::PocCompiler, &config));
        assert!(!graph.is_phase_enabled(&ScanPhase::ConfidenceScoring, &config));
        assert!(!graph.is_phase_enabled(&ScanPhase::VariantSearch, &config));
    }

    #[test]
    fn test_is_phase_enabled_default_config_values() {
        use crate::config;

        // Test which phases are enabled by default in ScannerConfig::default()
        let config = config::ScannerConfig::default();
        let graph = PhaseGraph::new();

        // These phases default to enabled (true)
        assert!(graph.is_phase_enabled(&ScanPhase::ConfidenceScoring, &config));
        assert!(graph.is_phase_enabled(&ScanPhase::CveBootstrap, &config));
        assert!(graph.is_phase_enabled(&ScanPhase::VariantSearch, &config));

        // These phases default to disabled (false)
        assert!(!graph.is_phase_enabled(&ScanPhase::ThreatModeling, &config));
        assert!(!graph.is_phase_enabled(&ScanPhase::RootCauseDedup, &config));
        assert!(!graph.is_phase_enabled(&ScanPhase::MultiVerifier, &config));
        assert!(!graph.is_phase_enabled(&ScanPhase::AutoPatching, &config));
        assert!(!graph.is_phase_enabled(&ScanPhase::PocCompiler, &config));
    }

    // ============================================================================
    // Orchestrator Tests
    // ============================================================================

    #[test]
    fn test_orchestrator_creation() {
        use crate::config;

        let config = config::ScannerConfig::default();
        let orchestrator = Orchestrator::new(&config);

        assert!(orchestrator.phase_graph().phases().len() > 0);
        // Verify config reference is stored (can't compare directly as ScannerConfig doesn't implement PartialEq)
        assert_eq!(orchestrator.config().scanner.commit_lookback_days, 0);
    }

    #[test]
    fn test_orchestrator_phase_graph_access() {
        use crate::config;

        let config = config::ScannerConfig::default();
        let orchestrator = Orchestrator::new(&config);

        let phase_graph = orchestrator.phase_graph();
        assert_eq!(phase_graph.phases().len(), 19);

        // Verify we can access metadata through orchestrator
        let indexing_meta = phase_graph.get_metadata(&ScanPhase::Indexing);
        assert!(indexing_meta.is_some());
        assert_eq!(indexing_meta.unwrap().display_name, "Indexing");
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
