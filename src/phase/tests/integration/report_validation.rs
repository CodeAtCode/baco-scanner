//! Report validation integration tests
//!
//! Tests JSON, HTML, and SARIF report generation and validation.

use crate::config::ScannerConfig;
use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use crate::phase::reporting::ReportingPhase;
use crate::phase::{PhaseContext, ScanPhase as PhaseTrait};
use crate::scanner::Scanner;
use std::fs;
use tempfile::TempDir;

use super::fixtures::create_test_project;
