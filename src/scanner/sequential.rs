//! Sequential phase execution utilities

use crate::checkpoint::ScanPhase;
use crate::scanner::phase_spec::PhaseSpec;

/// Get phase message for progress bar.
/// Delegates to PhaseSpec::progress_message, wrapping with phase_num/total_phases.
#[allow(dead_code)]
pub fn get_phase_message(phase: &ScanPhase, phase_num: usize, total_phases: usize) -> String {
    let base_msg = PhaseSpec::progress_message(phase);
    format!("Phase {}/{}: {}", phase_num, total_phases, base_msg)
}

// ============================================================================
