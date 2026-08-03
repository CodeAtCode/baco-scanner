//! Unit tests for src/scanner_types/
//!
//! Covers:
//! - CveEntry, CveSource, RootCauseGroup, CveCluster
//! - PatchCandidate, PatchValidationResult
//! - PoCCompileResult, VerifierVerdict
//! - Dependency, DependencyEcosystem, ProjectStack, MajorityVerdict
//! - SeverityRubric, AccessType, BlastRadius, V3Severity, RubricDimensions, RubricScore

use crate::fixtures::{
    verify_access_weights, verify_blast_radius_weights, verify_severity_mapping_boundaries,
};
use baco::scanner_types::{
    AccessType, BlastRadius, CveCluster, CveEntry, CveSource, Dependency, DependencyEcosystem,
    MajorityVerdict, PatchCandidate, PatchValidationResult, PoCCompileResult, ProjectStack,
    RootCauseGroup, RubricDimensions, RubricScore, SeverityRubric, V3Severity, VerifierVerdict,
};

// ============================================================================
// CveSource Tests
// ============================================================================

#[test]
fn test_cve_source_default_is_nvd() {
    let source = CveSource::default();
    assert_eq!(source, CveSource::NVD);
}

#[test]
fn test_cve_source_serialization() {
    let nvd = CveSource::NVD;
    let kev = CveSource::KEV;

    let nvd_json = serde_json::to_string(&nvd).unwrap();
    let kev_json = serde_json::to_string(&kev).unwrap();

    assert_eq!(nvd_json, "\"NVD\"");
    assert_eq!(kev_json, "\"KEV\"");
}

#[test]
fn test_cve_source_deserialization() {
    let nvd: CveSource = serde_json::from_str("\"NVD\"").unwrap();
    let kev: CveSource = serde_json::from_str("\"KEV\"").unwrap();

    assert_eq!(nvd, CveSource::NVD);
    assert_eq!(kev, CveSource::KEV);
}

// ============================================================================
// CveEntry Tests
// ============================================================================

#[test]
fn test_cve_entry_creation() {
    let cve = CveEntry::new(
        "CVE-2024-1234",
        "Test vulnerability description",
        V3Severity::High,
        CveSource::KEV,
    );

    assert_eq!(cve.cve_id, "CVE-2024-1234");
    assert_eq!(cve.description, "Test vulnerability description");
    assert_eq!(cve.severity, V3Severity::High);
    assert_eq!(cve.source, CveSource::KEV);
    assert!(cve.affected_products.is_empty());
    assert!(cve.published_date.is_none());
}

#[test]
fn test_cve_entry_default() {
    let cve = CveEntry::default();

    assert!(cve.cve_id.is_empty());
    assert!(cve.description.is_empty());
    assert_eq!(cve.severity, V3Severity::default());
    assert_eq!(cve.source, CveSource::default());
}

#[test]
fn test_cve_entry_serialization_roundtrip() {
    let cve = CveEntry {
        cve_id: "CVE-2024-5678".to_string(),
        description: "Serialization test".to_string(),
        severity: V3Severity::Critical,
        source: CveSource::NVD,
        affected_products: vec!["lib1".to_string(), "lib2".to_string()],
        published_date: Some("2024-01-01".to_string()),
    };

    let serialized = serde_json::to_string(&cve).unwrap();
    let deserialized: CveEntry = serde_json::from_str(&serialized).unwrap();

    assert_eq!(cve, deserialized);
}

// ============================================================================
// RootCauseGroup Tests
// ============================================================================

#[test]
fn test_root_cause_group_creation() {
    let group = RootCauseGroup::new(
        "sha256hash123",
        "Missing input validation",
        V3Severity::Critical,
    );

    assert_eq!(group.root_cause_id, "sha256hash123");
    assert_eq!(group.description, "Missing input validation");
    assert_eq!(group.severity, V3Severity::Critical);
    assert!(group.findings.is_empty());
    assert!(group.all_locations.is_empty());
}

#[test]
fn test_root_cause_group_add_finding() {
    let mut group = RootCauseGroup::new("abc123", "Buffer overflow", V3Severity::High);

    group.add_finding("finding-001", "src/main.rs", 42);
    group.add_finding("finding-002", "src/utils.rs", 156);
    group.add_finding("finding-003", "src/main.rs", 89);

    assert_eq!(group.findings.len(), 3);
    assert_eq!(group.all_locations.len(), 3);
    assert_eq!(group.findings[0], "finding-001");
    assert_eq!(group.all_locations[0], ("src/main.rs".to_string(), 42));
    assert_eq!(group.all_locations[1], ("src/utils.rs".to_string(), 156));
}

#[test]
fn test_root_cause_group_default() {
    let group = RootCauseGroup::default();

    assert!(group.root_cause_id.is_empty());
    assert!(group.findings.is_empty());
    assert!(group.all_locations.is_empty());
    assert_eq!(group.severity, V3Severity::default());
}

// ============================================================================
// CveCluster Tests
// ============================================================================

#[test]
fn test_cve_cluster_default() {
    let cluster = CveCluster::default();

    assert!(cluster.pattern_name.is_empty());
    assert_eq!(cluster.cve_count, 0);
    assert!(cluster.example_cves.is_empty());
    assert!(cluster.affected_dependencies.is_empty());
}

#[test]
fn test_cve_cluster_with_data() {
    let cluster = CveCluster {
        pattern_name: "sql-injection".to_string(),
        cve_count: 5,
        example_cves: vec!["CVE-2024-1111".to_string(), "CVE-2024-2222".to_string()],
        affected_dependencies: vec!["sqlparser".to_string()],
    };

    assert_eq!(cluster.pattern_name, "sql-injection");
    assert_eq!(cluster.cve_count, 5);
    assert_eq!(cluster.example_cves.len(), 2);
    assert_eq!(cluster.affected_dependencies.len(), 1);
}

// ============================================================================
// PatchValidationResult Tests
// ============================================================================

#[test]
fn test_patch_validation_result_success() {
    let result = PatchValidationResult::success();

    assert!(result.compiles);
    assert!(result.tests_pass);
    assert_eq!(result.warnings, 0);
    assert!(result.error_message.is_none());
}

#[test]
fn test_patch_validation_result_failure() {
    let result = PatchValidationResult::failure("Syntax error at line 42");

    assert!(!result.compiles);
    assert!(!result.tests_pass);
    assert_eq!(result.warnings, 0);
    assert_eq!(
        result.error_message,
        Some("Syntax error at line 42".to_string())
    );
}

#[test]
fn test_patch_validation_result_default() {
    let result = PatchValidationResult::default();

    assert!(!result.compiles);
    assert!(!result.tests_pass);
    assert_eq!(result.warnings, 0);
    assert!(result.error_message.is_none());
}

// ============================================================================
// PatchCandidate Tests
// ============================================================================

#[test]
fn test_patch_candidate_creation() {
    let diff = "--- a/src/main.rs\n+++ b/src/main.rs\n@@ -1 +1 @@\n-old\n+new\n";
    let patch = PatchCandidate::new(diff, "src/main.rs");

    assert_eq!(patch.diff, diff);
    assert_eq!(patch.file_path, "src/main.rs");
    assert!(!patch.applied);
    assert!(patch.validation_result.is_none());
}

#[test]
fn test_patch_candidate_default() {
    let patch = PatchCandidate::default();

    assert!(patch.diff.is_empty());
    assert!(patch.file_path.is_empty());
    assert!(!patch.applied);
    assert!(patch.validation_result.is_none());
}

#[test]
fn test_patch_candidate_with_validation() {
    let mut patch = PatchCandidate::new("diff content", "src/lib.rs");
    patch.validation_result = Some(PatchValidationResult::success());

    assert!(patch.validation_result.is_some());
    let validation = patch.validation_result.as_ref().unwrap();
    assert!(validation.compiles);
    assert!(validation.tests_pass);
}

// ============================================================================
// VerifierVerdict Tests
// ============================================================================

#[test]
fn test_verifier_verdict_default_is_inconclusive() {
    let verdict = VerifierVerdict::default();
    assert_eq!(verdict, VerifierVerdict::Inconclusive);
}

#[test]
fn test_verifier_verdict_all_variants() {
    let confirmed = VerifierVerdict::Confirmed;
    let rejected = VerifierVerdict::Rejected;
    let inconclusive = VerifierVerdict::Inconclusive;

    assert_ne!(confirmed, rejected);
    assert_ne!(confirmed, inconclusive);
    assert_ne!(rejected, inconclusive);
}

#[test]
fn test_verifier_verdict_serialization() {
    let confirmed = serde_json::to_string(&VerifierVerdict::Confirmed).unwrap();
    let rejected = serde_json::to_string(&VerifierVerdict::Rejected).unwrap();
    let inconclusive = serde_json::to_string(&VerifierVerdict::Inconclusive).unwrap();

    assert_eq!(confirmed, "\"Confirmed\"");
    assert_eq!(rejected, "\"Rejected\"");
    assert_eq!(inconclusive, "\"Inconclusive\"");
}

// ============================================================================
// PoCCompileResult Tests
// ============================================================================

#[test]
fn test_poc_compile_result_success() {
    let result = PoCCompileResult::success("rust");

    assert_eq!(result.language, "rust");
    assert!(result.compiles);
    assert!(result.errors.is_empty());
}

#[test]
fn test_poc_compile_result_failure() {
    let errors = vec![
        "error: expected semicolon".to_string(),
        "error: type mismatch".to_string(),
    ];
    let result = PoCCompileResult::failure("python", errors.clone());

    assert_eq!(result.language, "python");
    assert!(!result.compiles);
    assert_eq!(result.errors.len(), 2);
    assert_eq!(result.errors[0], "error: expected semicolon");
}

#[test]
fn test_poc_compile_result_default() {
    let result = PoCCompileResult::default();

    assert!(result.language.is_empty());
    assert!(!result.compiles);
    assert!(result.errors.is_empty());
}

// ============================================================================
// DependencyEcosystem Tests
// ============================================================================

#[test]
fn test_dependency_ecosystem_default_is_cratesio() {
    let ecosystem = DependencyEcosystem::default();
    assert_eq!(ecosystem, DependencyEcosystem::CratesIo);
}

#[test]
fn test_dependency_ecosystem_all_variants() {
    let ecosystems = [
        DependencyEcosystem::CratesIo,
        DependencyEcosystem::Npm,
        DependencyEcosystem::PyPi,
        DependencyEcosystem::Maven,
        DependencyEcosystem::GoModules,
    ];

    assert_eq!(ecosystems.len(), 5);
}

#[test]
fn test_dependency_ecosystem_serialization() {
    let cratesio = serde_json::to_string(&DependencyEcosystem::CratesIo).unwrap();
    let npm = serde_json::to_string(&DependencyEcosystem::Npm).unwrap();

    assert_eq!(cratesio, "\"CratesIo\"");
    assert_eq!(npm, "\"Npm\"");
}

// ============================================================================
// Dependency Tests
// ============================================================================

#[test]
fn test_dependency_default() {
    let dep = Dependency::default();

    assert!(dep.name.is_empty());
    assert!(dep.version.is_empty());
    assert_eq!(dep.ecosystem, DependencyEcosystem::default());
}

#[test]
fn test_dependency_with_values() {
    let dep = Dependency {
        name: "serde".to_string(),
        version: "1.0.193".to_string(),
        ecosystem: DependencyEcosystem::CratesIo,
    };

    assert_eq!(dep.name, "serde");
    assert_eq!(dep.version, "1.0.193");
    assert_eq!(dep.ecosystem, DependencyEcosystem::CratesIo);
}

// ============================================================================
// ProjectStack Tests
// ============================================================================

#[test]
fn test_project_stack_default() {
    let stack = ProjectStack::default();

    assert!(stack.languages.is_empty());
    assert!(stack.frameworks.is_empty());
    assert!(stack.dependencies.is_empty());
}

#[test]
fn test_project_stack_with_data() {
    let mut stack = ProjectStack {
        languages: vec!["rust".to_string(), "typescript".to_string()],
        frameworks: vec!["axum".to_string(), "nextjs".to_string()],
        dependencies: vec![
            Dependency {
                name: "tokio".to_string(),
                version: "1.35.0".to_string(),
                ecosystem: DependencyEcosystem::CratesIo,
            },
            Dependency {
                name: "express".to_string(),
                version: "4.18.2".to_string(),
                ecosystem: DependencyEcosystem::Npm,
            },
        ],
    };

    assert_eq!(stack.languages.len(), 2);
    assert_eq!(stack.frameworks.len(), 2);
    assert_eq!(stack.dependencies.len(), 2);

    stack.languages.push("python".to_string());
    assert_eq!(stack.languages.len(), 3);
}

// ============================================================================
// MajorityVerdict Tests
// ============================================================================

#[test]
fn test_majority_verdict_new() {
    let verdicts = vec![
        VerifierVerdict::Confirmed,
        VerifierVerdict::Rejected,
        VerifierVerdict::Confirmed,
    ];

    let majority = MajorityVerdict::new(VerifierVerdict::Confirmed, 0.67, verdicts.clone());

    assert_eq!(majority.final_verdict, VerifierVerdict::Confirmed);
    assert_eq!(majority.confidence, 0.67);
    assert_eq!(majority.verdicts.len(), 3);

    let confirmed_count = majority
        .vote_count
        .get(&VerifierVerdict::Confirmed)
        .unwrap();
    assert_eq!(*confirmed_count, 2);

    let rejected_count = majority.vote_count.get(&VerifierVerdict::Rejected).unwrap();
    assert_eq!(*rejected_count, 1);
}

#[test]
fn test_majority_verdict_unanimous() {
    let verdicts = vec![
        VerifierVerdict::Rejected,
        VerifierVerdict::Rejected,
        VerifierVerdict::Rejected,
        VerifierVerdict::Rejected,
    ];

    let majority = MajorityVerdict::new(VerifierVerdict::Rejected, 1.0, verdicts);

    assert_eq!(majority.final_verdict, VerifierVerdict::Rejected);
    assert_eq!(majority.confidence, 1.0);
    assert_eq!(majority.vote_count.len(), 1);
}

#[test]
fn test_majority_verdict_empty_verdicts() {
    let majority = MajorityVerdict::new(VerifierVerdict::Inconclusive, 0.0, vec![]);

    assert_eq!(majority.final_verdict, VerifierVerdict::Inconclusive);
    assert_eq!(majority.confidence, 0.0);
    assert!(majority.vote_count.is_empty());
}

#[test]
fn test_majority_verdict_default() {
    let majority = MajorityVerdict::default();

    assert_eq!(majority.final_verdict, VerifierVerdict::default());
    assert!(majority.vote_count.is_empty());
    assert_eq!(majority.confidence, 0.0);
    assert!(majority.verdicts.is_empty());
}

// ============================================================================
// AccessType Tests
// ============================================================================

#[test]
fn test_access_type_default_is_read() {
    let access = AccessType::default();
    assert_eq!(access, AccessType::Read);
}

#[test]
fn test_access_type_all_variants() {
    let read = AccessType::Read;
    let write = AccessType::Write;
    let both = AccessType::Both;

    assert_ne!(read, write);
    assert_ne!(read, both);
    assert_ne!(write, both);
}

#[test]
fn test_access_type_serialization() {
    let read = serde_json::to_string(&AccessType::Read).unwrap();
    let write = serde_json::to_string(&AccessType::Write).unwrap();
    let both = serde_json::to_string(&AccessType::Both).unwrap();

    assert_eq!(read, "\"Read\"");
    assert_eq!(write, "\"Write\"");
    assert_eq!(both, "\"Both\"");
}

// ============================================================================
// BlastRadius Tests
// ============================================================================

#[test]
fn test_blast_radius_default_is_high() {
    let radius = BlastRadius::default();
    assert_eq!(radius, BlastRadius::High);
}

fn assert_enum_variants_distinct<T: PartialEq + std::fmt::Debug>(variants: &[T], name: &str) {
    for (i, v1) in variants.iter().enumerate() {
        for (j, v2) in variants.iter().enumerate() {
            if i != j {
                assert_ne!(
                    v1, v2,
                    "{} variants at indices {} and {} should be distinct",
                    name, i, j
                );
            }
        }
    }
}

#[test]
fn test_blast_radius_all_variants() {
    let variants = vec![
        BlastRadius::Low,
        BlastRadius::Medium,
        BlastRadius::High,
        BlastRadius::Critical,
    ];
    assert_enum_variants_distinct(&variants, "BlastRadius");
}

#[test]
fn test_blast_radius_serialization() {
    let low = serde_json::to_string(&BlastRadius::Low).unwrap();
    let critical = serde_json::to_string(&BlastRadius::Critical).unwrap();

    assert_eq!(low, "\"Low\"");
    assert_eq!(critical, "\"Critical\"");
}

// ============================================================================
// V3Severity Tests
// ============================================================================

#[test]
fn test_v3_severity_default_is_low() {
    let severity = V3Severity::default();
    assert_eq!(severity, V3Severity::Low);
}

#[test]
fn test_v3_severity_all_variants() {
    let variants = vec![
        V3Severity::Low,
        V3Severity::Medium,
        V3Severity::High,
        V3Severity::Critical,
    ];
    assert_enum_variants_distinct(&variants, "V3Severity");
}

#[test]
fn test_v3_severity_serialization() {
    let low = serde_json::to_string(&V3Severity::Low).unwrap();
    let critical = serde_json::to_string(&V3Severity::Critical).unwrap();

    assert_eq!(low, "\"Low\"");
    assert_eq!(critical, "\"Critical\"");
}

// ============================================================================
// SeverityRubric Tests
// ============================================================================

#[test]
fn test_severity_rubric_default() {
    let rubric = SeverityRubric::default();

    assert_eq!(rubric.reachability, 0.5);
    assert_eq!(rubric.attacker_control, 0.5);
    assert_eq!(rubric.preconditions_factor, 0.5);
    assert!(!rubric.auth_required);
    assert_eq!(rubric.access_type, AccessType::Read);
    assert_eq!(rubric.blast_radius, BlastRadius::Medium);
}

#[test]
fn test_severity_rubric_new_with_valid_values() {
    let rubric = SeverityRubric::new(0.8, 0.9, 0.7, true, AccessType::Both, BlastRadius::Critical);

    assert_eq!(rubric.reachability, 0.8);
    assert_eq!(rubric.attacker_control, 0.9);
    assert_eq!(rubric.preconditions_factor, 0.7);
    assert!(rubric.auth_required);
    assert_eq!(rubric.access_type, AccessType::Both);
    assert_eq!(rubric.blast_radius, BlastRadius::Critical);
}

#[test]
fn test_severity_rubric_clamps_values() {
    let rubric = SeverityRubric::new(
        1.5,  // exceeds 1.0
        -0.5, // below 0.0
        2.0,  // exceeds 1.0
        false,
        AccessType::Read,
        BlastRadius::Low,
    );

    assert_eq!(rubric.reachability, 1.0);
    assert_eq!(rubric.attacker_control, 0.0);
    assert_eq!(rubric.preconditions_factor, 1.0);
}

#[test]
fn test_severity_rubric_auth_factor() {
    let rubric_with_auth =
        SeverityRubric::new(0.5, 0.5, 0.5, true, AccessType::Read, BlastRadius::Low);
    let rubric_without_auth =
        SeverityRubric::new(0.5, 0.5, 0.5, false, AccessType::Read, BlastRadius::Low);

    assert_eq!(rubric_with_auth.auth_factor(), 0.5);
    assert_eq!(rubric_without_auth.auth_factor(), 1.0);
}

#[test]
fn test_severity_rubric_access_weight() {
    verify_access_weights();
}

#[test]
fn test_severity_rubric_blast_radius_weight() {
    verify_blast_radius_weights();
}

#[test]
fn test_severity_rubric_serialization_roundtrip() {
    let rubric = SeverityRubric::new(0.8, 0.9, 0.7, true, AccessType::Both, BlastRadius::Critical);

    let serialized = serde_json::to_string(&rubric).unwrap();
    let deserialized: SeverityRubric = serde_json::from_str(&serialized).unwrap();

    assert_eq!(rubric, deserialized);
}

// ============================================================================
// RubricDimensions Tests
// ============================================================================

#[test]
fn test_rubric_dimensions_from_rubric() {
    let rubric = SeverityRubric::new(0.9, 0.8, 0.6, true, AccessType::Write, BlastRadius::High);

    let dimensions = RubricDimensions::from(rubric);

    assert_eq!(dimensions.reachability, 0.9);
    assert_eq!(dimensions.attacker_control, 0.8);
    assert_eq!(dimensions.preconditions_factor, 0.6);
    assert!(dimensions.auth_required);
    assert_eq!(dimensions.access_type, AccessType::Write);
    assert_eq!(dimensions.blast_radius, BlastRadius::High);
}

// ============================================================================
// RubricScore Tests
// ============================================================================

#[test]
fn test_rubric_score_new() {
    let dimensions = RubricDimensions {
        reachability: 0.5,
        attacker_control: 0.5,
        preconditions_factor: 0.5,
        auth_required: false,
        access_type: AccessType::Read,
        blast_radius: BlastRadius::Medium,
    };

    let score = RubricScore::new(0.75, dimensions.clone(), None);

    assert_eq!(score.raw_score, 0.75);
    assert_eq!(score.dimensions, dimensions);
    assert!(score.severity_override.is_none());
}

#[test]
fn test_rubric_score_clamps_raw_score() {
    let dimensions = RubricDimensions::from(SeverityRubric::default());

    let score_low = RubricScore::new(-0.5, dimensions.clone(), None);
    let score_high = RubricScore::new(1.5, dimensions.clone(), None);

    assert_eq!(score_low.raw_score, 0.0);
    assert_eq!(score_high.raw_score, 1.0);
}

#[test]
fn test_rubric_score_severity_with_override() {
    let dimensions = RubricDimensions::from(SeverityRubric::default());
    let score = RubricScore::new(0.1, dimensions.clone(), Some(V3Severity::Critical));

    // Override should take precedence even though raw score is low
    assert_eq!(score.severity(), V3Severity::Critical);
}

#[test]
fn test_rubric_score_severity_without_override() {
    let dimensions = RubricDimensions::from(SeverityRubric::default());

    let score_critical = RubricScore::new(0.85, dimensions.clone(), None);
    let score_high = RubricScore::new(0.65, dimensions.clone(), None);
    let score_medium = RubricScore::new(0.35, dimensions.clone(), None);
    let score_low = RubricScore::new(0.1, dimensions.clone(), None);

    assert_eq!(score_critical.severity(), V3Severity::Critical);
    assert_eq!(score_high.severity(), V3Severity::High);
    assert_eq!(score_medium.severity(), V3Severity::Medium);
    assert_eq!(score_low.severity(), V3Severity::Low);
}

#[test]
fn test_rubric_score_map_to_severity() {
    verify_severity_mapping_boundaries();
}

#[test]
fn test_rubric_score_serialization_roundtrip() {
    let dimensions = RubricDimensions::from(SeverityRubric::new(
        0.8,
        0.9,
        0.7,
        true,
        AccessType::Both,
        BlastRadius::Critical,
    ));

    let score = RubricScore::new(0.92, dimensions.clone(), Some(V3Severity::Critical));

    let serialized = serde_json::to_string(&score).unwrap();
    let deserialized: RubricScore = serde_json::from_str(&serialized).unwrap();

    assert_eq!(score, deserialized);
}
