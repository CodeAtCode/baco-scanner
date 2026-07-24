/// Determinism tests: verify scanner produces identical results on repeated runs.
use std::collections::HashSet;

use baco::config::ScannerConfig;
use baco::findings::{Severity, VulnerabilityFinding};
use baco::indexer::FileIndex;
use baco::phase::indexing::IndexingPhase;
use baco::phase::llm_discovery::LlmDiscoveryPhase;
use baco::phase::llm_static::LlmStaticAnalysisPhase;
use baco::phase::semgrep::SemgrepPhase;
use baco::phase::{PhaseContext, ScanPhase};
use baco::scanner::Scanner;
use std::fs;
use tempfile::TempDir;

fn findings_fingerprint(findings: &[VulnerabilityFinding]) -> HashSet<String> {
    findings
        .iter()
        .map(|f| {
            let line = f.line_number.unwrap_or(0);
            let cwe = f.cwe_id.as_deref().unwrap_or("");
            format!("{}:{}:{}:{}", f.file_path, line, cwe, f.title)
        })
        .collect()
}

fn file_paths_set(index: &FileIndex) -> HashSet<String> {
    index
        .files
        .iter()
        .map(|f| f.path.to_string_lossy().to_string())
        .collect()
}

fn index_project(path: &std::path::Path) -> Result<FileIndex, std::io::Error> {
    FileIndex::index_project(
        path.to_str().unwrap(),
        &["rust".to_string(), "python".to_string()],
        512 * 1024,
        &[],
    )
}

async fn run_parallel_phases(scanner: &mut Scanner) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();
    let mut analyzed_files = Vec::new();

    if let Ok(idx) = IndexingPhase
        .execute(&mut PhaseContext {
            scanner,
            analyzed_files: &mut analyzed_files,
        })
        .await
    {
        findings.extend(idx);
    }

    if let Ok(sg) = SemgrepPhase
        .execute(&mut PhaseContext {
            scanner,
            analyzed_files: &mut analyzed_files,
        })
        .await
    {
        findings.extend(sg);
    }

    if let Ok(llm) = LlmStaticAnalysisPhase
        .execute(&mut PhaseContext {
            scanner,
            analyzed_files: &mut analyzed_files,
        })
        .await
    {
        findings.extend(llm);
    }

    findings
}

fn make_seeded_finding(title: &str, file: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: VulnerabilityFinding::generate_id(file, Some(1), "CWE-20"),
        title: title.to_string(),
        description: "Seeded test finding".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.5,
        cwe_id: Some("CWE-20".to_string()),
        file_path: file.to_string(),
        line_number: Some(1),
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["seeded".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: None,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
    }
}

/// Indexing is purely filesystem-based and must be 100% deterministic.
#[tokio::test]
async fn test_indexing_determinism_same_fixture() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("main.rs"), "fn main() {}").unwrap();
    fs::write(temp_dir.path().join("lib.rs"), "pub fn lib() {}").unwrap();
    fs::write(temp_dir.path().join("test.py"), "print(1)").unwrap();

    let paths1 = file_paths_set(&index_project(temp_dir.path()).unwrap());
    let paths2 = file_paths_set(&index_project(temp_dir.path()).unwrap());

    assert_eq!(
        paths1, paths2,
        "FileIndex results must be identical across two runs"
    );
    assert!(paths1.len() >= 3, "At least 3 files should be indexed");
}

/// Large file set: determinism under scale.
#[tokio::test]
async fn test_indexing_determinism_many_files() {
    let temp_dir = TempDir::new().unwrap();

    for i in 0..20 {
        fs::write(
            temp_dir.path().join(format!("mod{i}.rs")),
            format!("pub fn func_{}() {{}}", i),
        )
        .unwrap();
    }

    let paths1 = file_paths_set(&index_project(temp_dir.path()).unwrap());
    let paths2 = file_paths_set(&index_project(temp_dir.path()).unwrap());

    assert_eq!(
        paths1, paths2,
        "Large project indexing must be deterministic"
    );
    assert!(paths1.len() >= 20, "All 20 files should be indexed");
}

/// Full parallel phases: two scanners on the same fixture yield identical findings.
#[tokio::test]
async fn test_parallel_phases_determinism_same_fixture() {
    let temp_dir = TempDir::new().unwrap();
    let py_dir = temp_dir.path().join("src");
    fs::create_dir_all(&py_dir).unwrap();

    fs::write(
        temp_dir.path().join("src").join("main.py"),
        r#"import sqlite3
def get_user(user_id):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE id = " + user_id
    return conn.execute(query).fetchall()
"#,
    )
    .unwrap();

    fs::write(
        temp_dir.path().join("src").join("utils.py"),
        r#"DB_PASSWORD = "hardcoded_secret_123"
def connect():
    return f"postgresql://admin:{DB_PASSWORD}@localhost/db"
"#,
    )
    .unwrap();

    let findings1 = {
        let config = ScannerConfig::default();
        let mut s = Scanner::new(config, temp_dir.path().to_path_buf(), false);
        run_parallel_phases(&mut s).await
    };

    let findings2 = {
        let config = ScannerConfig::default();
        let mut s = Scanner::new(config, temp_dir.path().to_path_buf(), false);
        run_parallel_phases(&mut s).await
    };

    assert_eq!(
        findings1.len(),
        findings2.len(),
        "Findings count should match across two runs"
    );

    let fp1 = findings_fingerprint(&findings1);
    let fp2 = findings_fingerprint(&findings2);
    assert_eq!(fp1, fp2, "Findings content should match across two runs");
}

/// Seeded findings through LlmDiscovery: two runs yield identical results.
#[tokio::test]
async fn test_seeded_findings_determinism() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("app.rs"), "fn x() {}").unwrap();

    let seeded = vec![
        make_seeded_finding("Input validation missing", "app.rs"),
        make_seeded_finding("Hardcoded credentials", "config.rs"),
    ];

    let result1 = {
        let config = ScannerConfig::default();
        let mut s = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);
        s.update_findings(seeded.clone());
        let mut analyzed_files = Vec::new();
        LlmDiscoveryPhase
            .execute(&mut PhaseContext {
                scanner: &mut s,
                analyzed_files: &mut analyzed_files,
            })
            .await
            .unwrap()
    };

    let result2 = {
        let config = ScannerConfig::default();
        let mut s = Scanner::new(config, temp_dir.path().to_path_buf(), false);
        s.update_findings(seeded.clone());
        let mut analyzed_files = Vec::new();
        LlmDiscoveryPhase
            .execute(&mut PhaseContext {
                scanner: &mut s,
                analyzed_files: &mut analyzed_files,
            })
            .await
            .unwrap()
    };

    assert_eq!(result1.len(), seeded.len());
    assert_eq!(result2.len(), seeded.len());

    let fp1 = findings_fingerprint(&result1);
    let fp2 = findings_fingerprint(&result2);
    assert_eq!(
        fp1, fp2,
        "Seeded findings must survive discovery phase identically"
    );
}

/// Two different projects should each produce deterministic file sets.
#[tokio::test]
async fn test_multi_project_indexing_determinism() {
    let project_a = TempDir::new().unwrap();
    let project_b = TempDir::new().unwrap();

    fs::write(project_a.path().join("main.rs"), "fn main() {}").unwrap();
    fs::write(project_a.path().join("lib.rs"), "pub fn lib() {}").unwrap();

    fs::write(project_b.path().join("app.py"), "print('hi')").unwrap();
    fs::write(project_b.path().join("index.js"), "console.log(1)").unwrap();

    let paths_a1 = file_paths_set(&index_project(project_a.path()).unwrap());
    let paths_a2 = file_paths_set(&index_project(project_a.path()).unwrap());
    assert_eq!(
        paths_a1, paths_a2,
        "Project A indexing must be deterministic"
    );

    let paths_b1 = file_paths_set(&index_project(project_b.path()).unwrap());
    let paths_b2 = file_paths_set(&index_project(project_b.path()).unwrap());
    assert_eq!(
        paths_b1, paths_b2,
        "Project B indexing must be deterministic"
    );

    assert_ne!(
        paths_a1, paths_b1,
        "Different projects yield different file sets"
    );
}

/// End-to-end: run the vulnerable-project fixture twice and compare findings.
#[tokio::test]
async fn test_fixture_project_determinism() {
    let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/vulnerable-project");

    if !fixture_path.is_dir() {
        return;
    }

    let findings1 = {
        let config = ScannerConfig::default();
        let mut s = Scanner::new(config.clone(), fixture_path.clone(), false);
        run_parallel_phases(&mut s).await
    };

    let findings2 = {
        let config = ScannerConfig::default();
        let mut s = Scanner::new(config, fixture_path, false);
        run_parallel_phases(&mut s).await
    };

    assert_eq!(
        findings1.len(),
        findings2.len(),
        "Fixture findings count should match"
    );

    let fp1 = findings_fingerprint(&findings1);
    let fp2 = findings_fingerprint(&findings2);
    assert_eq!(fp1, fp2, "Fixture findings must be deterministic");
}

/// Edge case: empty project should deterministically produce zero findings.
#[tokio::test]
async fn test_empty_project_determinism() {
    let temp_dir = TempDir::new().unwrap();

    let findings1 = {
        let config = ScannerConfig::default();
        let mut s = Scanner::new(config, temp_dir.path().to_path_buf(), false);
        run_parallel_phases(&mut s).await
    };

    let findings2 = {
        let config = ScannerConfig::default();
        let mut s = Scanner::new(config, temp_dir.path().to_path_buf(), false);
        run_parallel_phases(&mut s).await
    };

    assert_eq!(
        findings1.len(),
        0,
        "Empty project yields no findings (run 1)"
    );
    assert_eq!(
        findings2.len(),
        0,
        "Empty project yields no findings (run 2)"
    );
    assert_eq!(
        findings1.len(),
        findings2.len(),
        "Both empty runs produce zero findings"
    );
}
