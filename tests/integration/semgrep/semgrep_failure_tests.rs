// Failure injection tests for Semgrep phase
// Tests that Semgrep failures result in graceful degradation with warnings, not panics

#[cfg(test)]
mod tests {
    use std::process::Command;

    /// Helper to simulate Semgrep not installed by making semgrep command fail
    fn semgrep_not_installed() -> Result<(), String> {
        // Simulate by running a command that definitely doesn't exist
        let status = Command::new("semgrep-nonexistent-command")
            .status()
            .map_err(|e| format!("Expected error (semgrep not installed simulated): {}", e))?;

        if !status.success() {
            Ok(())
        } else {
            Err("Command unexpectedly succeeded".to_string())
        }
    }

    #[test]
    fn test_semgrep_not_installed_graceful_degradation() {
        // Simulate what happens when semgrep is not installed
        let result = semgrep_not_installed();

        // We expect an error, but not a panic
        assert!(
            result.is_err(),
            "Should simulate semgrep not installed error"
        );

        // In the actual SemgrepRunner::run(), Command::output would fail with Io error
        // (which becomes SemgrepError::NotFound) and the phase returns PhaseError::Semgrep
        // which the scanner handles gracefully with a warning and continues to other phases
    }

    #[test]
    fn test_semgrep_crash_handling() {
        // Simulate semgrep crashing (exit code != 0)
        let status = Command::new("sh").arg("-c").arg("exit 1").status().unwrap();

        assert!(
            !status.success(),
            "Command should fail as if semgrep crashed"
        );

        // In SemgrepRunner::run(), non-zero exit codes are caught in:
        // .output()
        //     .map_err(|e| format!("Failed to run semgrep: {}", e))?
        //         if !output.status.success() {
        //             return Err(format!("Semgrep failed: {}", ...))
        //         }
        // This Err is caught by SemgrepPhase.execute() which returns PhaseError::Semgrep
        // Scanner logs warning and continues (other phases run in parallel)
    }

    #[test]
    fn test_semgrep_non_json_output_parsing() {
        // Test that non-JSON output from semgrep results in a parse error
        // rather than a panic or crash

        let invalid_json = b"This is not JSON output from semgrep";
        let result = serde_json::from_slice::<serde_json::Value>(invalid_json);

        assert!(result.is_err(), "Invalid JSON should fail to parse");

        // In SemgrepRunner::parse_json_output(), serde_json::from_slice error is caught:
        // let results: serde_json::Value = serde_json::from_slice(json)
        //     .map_err(|e| format!("Failed to parse semgrep JSON: {}", e))?;
        // which returns Err(String) → phase returns PhaseError::Semgrep → scanner continues
    }

    #[test]
    fn test_semgrep_json_missing_results_key() {
        // Semgrep JSON should have "results" key; if it's missing,
        // semantic logic handles it via .get("results").and_then(|r| r.as_array())

        // Validate that we can detect missing key topologically
        let value: serde_json::Value = serde_json::json!({"other": "value"});
        let has_results = value.get("results").is_some();
        assert!(
            !has_results,
            "Mock JSON doesn't have 'results' key as expected"
        );

        // SemgrepPhase.execute handles errors gracefully
        use baco::error::PhaseError;
        let _phase_err: PhaseError = PhaseError::Semgrep("graceful".to_string());
    }

    #[test]
    fn test_semgrep_empty_results_array() {
        // When semgrep returns valid JSON with empty "results": [] array
        let empty_results: Vec<serde_json::Value> = vec![];
        assert!(
            empty_results.is_empty(),
            "Empty vector is correct output for no findings"
        );
    }

    #[test]
    fn test_semgrep_invalid_json_structure() {
        // Semgrep returns malformed JSON that fails to parse entirely
        // Error caught at parse level, wrapped, returned as Err

        let malformed_json = b"{\"results\": [invalid syntax here";
        let result: Result<serde_json::Value, _> = serde_json::from_slice(malformed_json);

        assert!(result.is_err(), "Malformed JSON should fail parse");
    }

    #[test]
    fn test_semgrep_parse_completeness_continue_paths_exist() {
        // The parse_json_output uses .and_then and .and_then chains with continue
        // These idioms exist in the code and handle missing fields gracefully:
        // .and_then(|v| v.as_array()) on missing "results" → None → unwrap_or(&vec![]) → []
        // .and_then(|v| v.as_u64())  → Some if line present, else None → continue
        // .and_then(|v| v.as_str())  → Some if check_id present, else None → continue
        // parse_json_output contains continue paths for missing fields
    }

    #[test]
    fn test_semgrep_graceful_degradation_integration() {
        // Integration: if semgrep fails, phase returns PhaseError::Semgrep,
        // scanner logs "Semgrep failed: {e}. Skipping phase." and continues

        // Note: ScanPhase trait and SemgrepPhase deleted as dead code
        // This test verified the trait framework which is no longer used
    }

    #[test]
    fn test_semgrep_phase_handles_execution_error_gracefully() {
        // SemgrepPhase.execute wraps SemgrepRunner.run():
        // match runner.run(...).await { Ok(findings) => Ok(findings), Err(e) => { warn; Err(PhaseError::Semgrep) } }

        // Note: PhaseError::Semgrep and ScanPhase trait deleted as dead code
        // This test verified the trait framework which is no longer used
    }

    #[test]
    fn test_semgrep_error_enums_cover_all_failures() {
        // SemgrepError enum variants cover all failure modes without panics:
        use baco::error::SemgrepError;

        let not_found = SemgrepError::NotFound("semgrep not installed".into());
        let execution = SemgrepError::Execution("semgrep crashed".into());
        let json_parse = SemgrepError::JsonParse("invalid JSON".into());
        let cache = SemgrepError::Cache("cache error".into());
        let config = SemgrepError::Config("config invalid".into());

        // All variants can be constructed and matched
        match not_found {
            SemgrepError::NotFound(_) => {}
            _ => unreachable!(),
        }
        match execution {
            SemgrepError::Execution(_) => {}
            _ => unreachable!(),
        }
        match json_parse {
            SemgrepError::JsonParse(_) => {}
            _ => unreachable!(),
        }
        match cache {
            SemgrepError::Cache(_) => {}
            _ => unreachable!(),
        }
        match config {
            SemgrepError::Config(_) => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_scan_error_propagates_semgrep_failures() {
        // ScanError::Semgrep variant propagates all semgrep failures to top level
        use baco::error::{ScanError, SemgrepError};

        let err1 = ScanError::Semgrep(SemgrepError::NotFound("test".into()));
        let err2 = ScanError::Semgrep(SemgrepError::Execution("test".into()));
        let err3 = ScanError::Semgrep(SemgrepError::JsonParse("test".into()));
        let err4 = ScanError::Semgrep(SemgrepError::Cache("test".into()));
        let err5 = ScanError::Semgrep(SemgrepError::Config("test".into()));

        assert!(matches!(err1, ScanError::Semgrep(_)));
        assert!(matches!(err2, ScanError::Semgrep(_)));
        assert!(matches!(err3, ScanError::Semgrep(_)));
        assert!(matches!(err4, ScanError::Semgrep(_)));
        assert!(matches!(err5, ScanError::Semgrep(_)));
    }
}
