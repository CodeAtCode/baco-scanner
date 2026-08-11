use baco::checkpoint::{Checkpoint, ScanPhase};
use std::path::PathBuf;

#[test]
fn test_checkpoint_new_default() {
    let now = chrono::Utc::now();
    let cp = Checkpoint::new("scan-1", "/tmp/project", now);

    assert_eq!(cp.scan_id, "scan-1");
    assert_eq!(cp.project_path, "/tmp/project");
    assert_eq!(cp.current_phase, ScanPhase::Indexing);
    assert!(cp.completed_phases.is_empty());
    assert!(cp.findings_so_far.is_empty());
    assert_eq!(cp.file_count, 0);
    assert!(cp.analyzed_files.is_empty());
}

#[test]
fn test_checkpoint_save_load_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("checkpoint.json");
    let path_str = path.to_str().unwrap();

    let now = chrono::Utc::now();
    let mut cp = Checkpoint::new("test-scan", "/tmp/proj", now);
    cp.completed_phases.push(ScanPhase::Indexing);
    cp.completed_phases.push(ScanPhase::Semgrep);
    cp.file_count = 42;

    cp.save(path_str).unwrap();
    assert!(path.exists());

    let loaded = Checkpoint::load(path_str).unwrap();
    assert_eq!(loaded.scan_id, "test-scan");
    assert_eq!(loaded.project_path, "/tmp/proj");
    assert_eq!(loaded.current_phase, ScanPhase::Indexing);
    assert_eq!(loaded.completed_phases.len(), 2);
    assert_eq!(loaded.file_count, 42);
}

#[test]
fn test_checkpoint_save_creates_parent_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp
        .path()
        .join("nested")
        .join("dir")
        .join("checkpoint.json");
    let path_str = path.to_str().unwrap();

    let now = chrono::Utc::now();
    let cp = Checkpoint::new("deep", "/tmp/p", now);

    cp.save(path_str).unwrap();
    assert!(path.exists());
}

#[test]
fn test_checkpoint_validate_empty_scan_id() {
    let now = chrono::Utc::now();
    let mut cp = Checkpoint::new("", "/tmp/p", now);
    cp.current_phase = ScanPhase::Indexing;

    let result = cp.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("scan_id"));
}

#[test]
fn test_checkpoint_validate_empty_project_path() {
    let now = chrono::Utc::now();
    let mut cp = Checkpoint::new("scan-1", "", now);
    cp.current_phase = ScanPhase::Indexing;

    let result = cp.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("project_path"));
}

#[test]
fn test_checkpoint_validate_valid() {
    let now = chrono::Utc::now();
    let cp = Checkpoint::new("scan-1", "/tmp/p", now);
    assert!(cp.validate().is_ok());
}

#[test]
fn test_checkpoint_load_invalid_json() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bad.json");
    std::fs::write(&path, "not json at all").unwrap();

    let result = Checkpoint::load(path.to_str().unwrap());
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("parse"));
}

#[test]
fn test_checkpoint_load_missing_file() {
    let result = Checkpoint::load("/nonexistent/checkpoint.json");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("read"));
}

#[test]
fn test_resume_from_indexing() {
    let tmp = tempfile::tempdir().unwrap();
    let path = make_checkpoint_path(&tmp, ScanPhase::Indexing);
    let next = Checkpoint::resume_from(path.to_str().unwrap()).unwrap();
    assert_eq!(next, ScanPhase::Semgrep);
}

#[test]
fn test_resume_from_semgrep() {
    let tmp = tempfile::tempdir().unwrap();
    let path = make_checkpoint_path(&tmp, ScanPhase::Semgrep);
    let next = Checkpoint::resume_from(path.to_str().unwrap()).unwrap();
    assert_eq!(next, ScanPhase::CpgSlice);
}

#[test]
fn test_resume_from_llm_static() {
    let tmp = tempfile::tempdir().unwrap();
    let path = make_checkpoint_path(&tmp, ScanPhase::LlmStaticAnalysis);
    let next = Checkpoint::resume_from(path.to_str().unwrap()).unwrap();
    assert_eq!(next, ScanPhase::CweRouting);
}

#[test]
fn test_resume_from_cwe_routing() {
    let tmp = tempfile::tempdir().unwrap();
    let path = make_checkpoint_path(&tmp, ScanPhase::CweRouting);
    let next = Checkpoint::resume_from(path.to_str().unwrap()).unwrap();
    assert_eq!(next, ScanPhase::RuleSynthesis);
}

#[test]
fn test_resume_from_reporting() {
    let tmp = tempfile::tempdir().unwrap();
    let path = make_checkpoint_path(&tmp, ScanPhase::Reporting);
    let next = Checkpoint::resume_from(path.to_str().unwrap()).unwrap();
    assert_eq!(next, ScanPhase::Complete);
}

#[test]
fn test_resume_from_complete_restarts() {
    let tmp = tempfile::tempdir().unwrap();
    let path = make_checkpoint_path(&tmp, ScanPhase::Complete);
    let next = Checkpoint::resume_from(path.to_str().unwrap()).unwrap();
    assert_eq!(next, ScanPhase::Indexing);
}

#[test]
fn test_resume_from_error_restarts() {
    let tmp = tempfile::tempdir().unwrap();
    let path = make_checkpoint_path(&tmp, ScanPhase::Error);
    let next = Checkpoint::resume_from(path.to_str().unwrap()).unwrap();
    assert_eq!(next, ScanPhase::Indexing);
}

#[test]
fn test_resume_from_cpgslice() {
    let tmp = tempfile::tempdir().unwrap();
    let path = make_checkpoint_path(&tmp, ScanPhase::CpgSlice);
    let next = Checkpoint::resume_from(path.to_str().unwrap()).unwrap();
    assert_eq!(next, ScanPhase::LlmStaticAnalysis);
}

#[test]
fn test_resume_from_exploitsynth() {
    let tmp = tempfile::tempdir().unwrap();
    let path = make_checkpoint_path(&tmp, ScanPhase::ExploitSynth);
    let next = Checkpoint::resume_from(path.to_str().unwrap()).unwrap();
    assert_eq!(next, ScanPhase::VariantSearch);
}

#[test]
fn test_resume_full_sequential_chain() {
    let phases = vec![
        (ScanPhase::Semgrep, ScanPhase::CpgSlice),
        (ScanPhase::CpgSlice, ScanPhase::LlmStaticAnalysis),
        (ScanPhase::LlmStaticAnalysis, ScanPhase::CweRouting),
        (ScanPhase::CweRouting, ScanPhase::RuleSynthesis),
        (ScanPhase::RuleSynthesis, ScanPhase::LlmDiscovery),
        (ScanPhase::LlmDiscovery, ScanPhase::LlmVerification),
        (ScanPhase::LlmVerification, ScanPhase::Validate),
        (ScanPhase::Validate, ScanPhase::SecurityAgentVerification),
        (
            ScanPhase::SecurityAgentVerification,
            ScanPhase::TicketCrossRef,
        ),
        (ScanPhase::TicketCrossRef, ScanPhase::GitAnalysis),
        (ScanPhase::GitAnalysis, ScanPhase::CrossFileAnalysis),
        (ScanPhase::CrossFileAnalysis, ScanPhase::ConfidenceScoring),
        (ScanPhase::ConfidenceScoring, ScanPhase::AiAggregation),
        (ScanPhase::AiAggregation, ScanPhase::ThreatModeling),
        (ScanPhase::ThreatModeling, ScanPhase::RootCauseDedup),
        (ScanPhase::RootCauseDedup, ScanPhase::MultiVerifier),
        (ScanPhase::MultiVerifier, ScanPhase::AutoPatching),
        (ScanPhase::AutoPatching, ScanPhase::CveBootstrap),
        (ScanPhase::CveBootstrap, ScanPhase::PocCompiler),
        (ScanPhase::PocCompiler, ScanPhase::ExploitSynth),
        (ScanPhase::ExploitSynth, ScanPhase::VariantSearch),
        (ScanPhase::VariantSearch, ScanPhase::Reporting),
        (ScanPhase::Reporting, ScanPhase::Complete),
    ];

    let tmp = tempfile::tempdir().unwrap();
    for (current, expected_next) in phases {
        let path = make_checkpoint_path(&tmp, current.clone());
        let next = Checkpoint::resume_from(path.to_str().unwrap()).unwrap();
        assert_eq!(
            next, expected_next,
            "resume_from({:?}) should return {:?}",
            current, expected_next
        );
    }
}

#[test]
fn test_checkpoint_format_phase_cwe_routing() {
    let now = chrono::Utc::now();
    let cp = Checkpoint::new("s1", "/p", now);
    let formatted = cp.format_phase();
    // CweRouting should have a format entry (not crash)
    assert!(!formatted.is_empty());
}

fn make_checkpoint_path(tmp: &tempfile::TempDir, phase: ScanPhase) -> PathBuf {
    let path = tmp.path().join("checkpoint.json");
    let now = chrono::Utc::now();
    let mut cp = Checkpoint::new("test-scan", "/tmp/proj", now);
    cp.current_phase = phase;
    cp.save(path.to_str().unwrap()).unwrap();
    path
}
