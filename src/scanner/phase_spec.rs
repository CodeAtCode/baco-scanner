//! Single source of truth for the BACO 15-phase pipeline definition.
//!
//! This module defines the canonical pipeline structure: 3 parallel phases
//! followed by 12 sequential phases. All phase-related queries (order,
//! grouping, resume transitions, progress messages) derive from this table —
//! no redundant definitions elsewhere.

use crate::checkpoint::ScanPhase;

/// Phase execution mode: parallel (concurrent) or sequential (ordered).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseKind {
    Parallel,
    Sequential,
}

/// A single slot in the pipeline table, carrying all metadata needed for
/// phase queries without touching other modules.
#[derive(Debug, Clone)]
pub struct PhaseSlot {
    /// The phase this slot represents.
    pub phase: ScanPhase,
    /// Parallel or sequential execution mode.
    pub kind: PhaseKind,
    /// Executor key for dispatch.
    pub executor_key: &'static str,
}

/// The canonical 15-phase pipeline table.
///
/// Order: 3 parallel phases (Indexing, Semgrep, LlmStaticAnalysis) followed
/// by 12 sequential phases (CweRouting through Reporting).
pub struct PhaseSpec;

impl PhaseSpec {
    /// Returns the full 15-phase slot table.
    pub const fn slots() -> &'static [PhaseSlot; 15] {
        &SLOTS
    }

    /// Return all phases in execution order (15 total).
    pub fn all() -> &'static [ScanPhase; 15] {
        &ALL_PHASES
    }

    /// Return only the sequential phases (12 total).
    pub fn sequential() -> &'static [ScanPhase; 12] {
        &SEQUENTIAL_PHASES
    }

    /// Return only the parallel phases (3 total).
    pub fn parallel() -> &'static [ScanPhase; 3] {
        &PARALLEL_PHASES
    }

    /// Total phase count (15).
    pub const fn total() -> usize {
        15
    }

    /// Compute the next phase to resume from, given a completed phase.
    ///
    /// Byte-identical semantics to checkpoint::Checkpoint::resume_from.
    pub fn resume_from(phase: &ScanPhase) -> ScanPhase {
        match phase {
            // Parallel phases (run concurrently: Indexing, Semgrep, LlmStaticAnalysis)
            ScanPhase::Indexing => ScanPhase::Semgrep,
            ScanPhase::Semgrep => ScanPhase::LlmStaticAnalysis,
            ScanPhase::LlmStaticAnalysis => ScanPhase::CweRouting,
            // Sequential phases
            ScanPhase::CweRouting => ScanPhase::LlmDiscovery,
            ScanPhase::LlmDiscovery => ScanPhase::LlmVerification,
            ScanPhase::LlmVerification => ScanPhase::Validate,
            ScanPhase::Validate => ScanPhase::TicketCrossRef,
            ScanPhase::TicketCrossRef => ScanPhase::GitAnalysis,
            ScanPhase::GitAnalysis => ScanPhase::CrossFileAnalysis,
            ScanPhase::CrossFileAnalysis => ScanPhase::ConfidenceScoring,
            ScanPhase::ConfidenceScoring => ScanPhase::AiAggregation,
            ScanPhase::AiAggregation => ScanPhase::RootCauseDedup,
            ScanPhase::RootCauseDedup => ScanPhase::CveBootstrap,
            ScanPhase::CveBootstrap => ScanPhase::Reporting,
            ScanPhase::Reporting => ScanPhase::Complete,
            ScanPhase::Complete | ScanPhase::Error => ScanPhase::Indexing,
        }
    }

    /// Return the progress message for a given phase.
    pub fn progress_message(phase: &ScanPhase) -> &'static str {
        match phase {
            ScanPhase::CweRouting => "CWE routing (routing findings to specialized models)...",
            ScanPhase::LlmDiscovery => "LLM discovery (enriching findings with context)...",
            ScanPhase::LlmVerification => "LLM verification (validating findings)...",
            ScanPhase::Validate => "Validate (LLM-as-judge rationale validation)...",
            ScanPhase::TicketCrossRef => "Searching ticket systems for references...",
            ScanPhase::GitAnalysis => "Analyzing Git history for related commits...",
            ScanPhase::CrossFileAnalysis => "Cross-file dependency analysis...",
            ScanPhase::ConfidenceScoring => "Calculating confidence scores...",
            ScanPhase::AiAggregation => "AI aggregation (generating executive summary)...",
            ScanPhase::RootCauseDedup => "Root cause deduplication...",
            ScanPhase::CveBootstrap => "CVE bootstrap...",
            ScanPhase::Reporting => "Generating reports (JSON/HTML/SARIF)...",
            ScanPhase::Indexing => "Indexing project files...",
            ScanPhase::Semgrep => "Running Semgrep...",
            ScanPhase::LlmStaticAnalysis => "LLM static analysis...",
            ScanPhase::Complete => "Scan complete!",
            ScanPhase::Error => "Error occurred...",
        }
    }
}

// ============================================================================
// Static data: the canonical 15-phase table
// ============================================================================

const SLOTS: [PhaseSlot; 15] = [
    // Parallel phases (3)
    PhaseSlot {
        phase: ScanPhase::Indexing,
        kind: PhaseKind::Parallel,
        executor_key: "indexing",
    },
    PhaseSlot {
        phase: ScanPhase::Semgrep,
        kind: PhaseKind::Parallel,
        executor_key: "semgrep",
    },
    PhaseSlot {
        phase: ScanPhase::LlmStaticAnalysis,
        kind: PhaseKind::Parallel,
        executor_key: "llm_static",
    },
    // Sequential phases (12)
    PhaseSlot {
        phase: ScanPhase::CweRouting,
        kind: PhaseKind::Sequential,
        executor_key: "cwe_routing",
    },
    PhaseSlot {
        phase: ScanPhase::LlmDiscovery,
        kind: PhaseKind::Sequential,
        executor_key: "llm_discovery",
    },
    PhaseSlot {
        phase: ScanPhase::LlmVerification,
        kind: PhaseKind::Sequential,
        executor_key: "llm_verification",
    },
    PhaseSlot {
        phase: ScanPhase::Validate,
        kind: PhaseKind::Sequential,
        executor_key: "validate",
    },
    PhaseSlot {
        phase: ScanPhase::TicketCrossRef,
        kind: PhaseKind::Sequential,
        executor_key: "ticket_cross_ref",
    },
    PhaseSlot {
        phase: ScanPhase::GitAnalysis,
        kind: PhaseKind::Sequential,
        executor_key: "git_analysis",
    },
    PhaseSlot {
        phase: ScanPhase::CrossFileAnalysis,
        kind: PhaseKind::Sequential,
        executor_key: "cross_file_analysis",
    },
    PhaseSlot {
        phase: ScanPhase::ConfidenceScoring,
        kind: PhaseKind::Sequential,
        executor_key: "confidence_scoring",
    },
    PhaseSlot {
        phase: ScanPhase::AiAggregation,
        kind: PhaseKind::Sequential,
        executor_key: "ai_aggregation",
    },
    PhaseSlot {
        phase: ScanPhase::RootCauseDedup,
        kind: PhaseKind::Sequential,
        executor_key: "root_cause_dedup",
    },
    PhaseSlot {
        phase: ScanPhase::CveBootstrap,
        kind: PhaseKind::Sequential,
        executor_key: "cve_bootstrap",
    },
    PhaseSlot {
        phase: ScanPhase::Reporting,
        kind: PhaseKind::Sequential,
        executor_key: "reporting",
    },
];

// Derived static arrays for efficient queries

const ALL_PHASES: [ScanPhase; 15] = [
    ScanPhase::Indexing,
    ScanPhase::Semgrep,
    ScanPhase::LlmStaticAnalysis,
    ScanPhase::CweRouting,
    ScanPhase::LlmDiscovery,
    ScanPhase::LlmVerification,
    ScanPhase::Validate,
    ScanPhase::TicketCrossRef,
    ScanPhase::GitAnalysis,
    ScanPhase::CrossFileAnalysis,
    ScanPhase::ConfidenceScoring,
    ScanPhase::AiAggregation,
    ScanPhase::RootCauseDedup,
    ScanPhase::CveBootstrap,
    ScanPhase::Reporting,
];

const PARALLEL_PHASES: [ScanPhase; 3] = [
    ScanPhase::Indexing,
    ScanPhase::Semgrep,
    ScanPhase::LlmStaticAnalysis,
];

const SEQUENTIAL_PHASES: [ScanPhase; 12] = [
    ScanPhase::CweRouting,
    ScanPhase::LlmDiscovery,
    ScanPhase::LlmVerification,
    ScanPhase::Validate,
    ScanPhase::TicketCrossRef,
    ScanPhase::GitAnalysis,
    ScanPhase::CrossFileAnalysis,
    ScanPhase::ConfidenceScoring,
    ScanPhase::AiAggregation,
    ScanPhase::RootCauseDedup,
    ScanPhase::CveBootstrap,
    ScanPhase::Reporting,
];
