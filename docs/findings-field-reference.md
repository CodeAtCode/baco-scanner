# Findings Field Reference

This document describes the JSON output schema for the `VulnerabilityFinding` struct produced by baco's SAST scanner.

## Field Table

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| **Core Identification** |
| `id` | `String` | yes | Unique identifier for this finding (SHA256 hash of file path, line, CWE, rule ID, and code snippet) |
| `title` | `String` | yes | Human-readable title summarizing the vulnerability |
| `description` | `String` | yes | Detailed explanation of the vulnerability |
| `severity` | `Severity` | yes | Impact level: `critical`, `high`, `medium`, `low`, or `info` |
| `confidence_score` | `f32` | yes | Likelihood this is a true positive (0.0–1.0) |
| **Vulnerability Classification** |
| `cwe_id` | `Option<String>` | no | Common Weakness Enumeration identifier (e.g., "CWE-89") |
| **Location Information** |
| `file_path` | `String` | yes | Path to the file containing the vulnerability |
| `line_number` | `Option<u32>` | no | Exact line number where the vulnerability occurs |
| `code_snippet` | `Option<String>` | no | Extracted code showing the vulnerable pattern |
| `diff_hunk` | `Option<String>` | no | Unified diff showing vulnerable code and suggested fix |
| `code_location` | `Option<String>` | no | Human-readable location summary |
| `statement_range` | `Option<(u32, u32)>` | no | Statement-level localization: (start_line, end_line) of vulnerable statements; `None` means function-level only |
| **Remediation Guidance** |
| `recommendation` | `Option<String>` | no | Suggested fix or mitigation approach |
| `poc_code` | `Option<String>` | no | Generated Proof of Concept code snippet |
| `mitigation_code` | `Option<String>` | no | Safe version showing the recommended fix |
| `poc_format` | `Option<String>` | no | Format of PoC code: `rust`, `python`, `shell`, or `go` |
| **Detection Metadata** |
| `sources` | `Vec<String>` | yes | Detection sources that identified this finding (e.g., `semgrep_pattern`, `llm_verification`) |
| `commit_reference` | `Option<String>` | no | Git commit hash where the vulnerability was introduced |
| `ticket_reference` | `Option<String>` | no | Issue tracker ticket associated with this finding |
| `cross_file_references` | `Option<Vec<String>>` | no | Semgrep `path:line` locations referencing this finding |
| `related_finding_ids` | `Option<Vec<String>>` | no | IDs of related findings produced by the cross-file analyzer |
| `agent_evidence_path` | `Option<String>` | no | Path to agent-generated evidence files |
| `llm_model` | `Option<String>` | no | LLM model used for discovery or analysis |
| `agent_mode` | `bool` | no | Whether agent mode was used for this finding |
| **Priority & Triage** |
| `priority_score` | `Option<f32>` | no | Calculated priority score for ordering fixes |
| `triage_verdict` | `Option<TriageVerdict>` | no | Prioritization decision: `pass`, `kill`, `downgrade`, or `chain_required` |
| **Verification State** |
| `verification_status` | `Option<VerificationStatus>` | no | Verification state: `confirmed`, `false_positive`, `needs_review`, or `failed` |
| `verification_notes` | `Option<String>` | no | Human notes from verification process |
| `verification_error` | `Option<String>` | no | Error message if verification failed |
| `verification_tier` | `Option<VerificationTier>` | no | Evidence support level: `verified`, `supported`, or `unverified` |
| `verification_gate_answers` | `Option<Vec<(String, bool)>>` | no | Seven-question gate answers for audit trail |
| **Security Taxonomy** |
| `security_issue` | `Option<SecurityIssue>` | no | Extended security classification with CWE, OWASP, MITRE ATT&CK, and custom tags |
| **Supporting Evidence** |
| `evidence` | `Vec<Evidence>` | yes | Collection of evidence items supporting this finding |

## Type Definitions

### Severity
Impact level of the vulnerability:
- `critical`: Severe impact, immediate action required
- `high`: Significant impact, should be fixed soon
- `medium`: Moderate impact, fix when convenient
- `low`: Minor impact, low priority
- `info`: Informational finding, no immediate action

### VerificationStatus
State of the verification process:
- `confirmed`: Verified as a real vulnerability
- `false_positive`: Verified as not a vulnerability
- `needs_review`: Not yet verified, requires investigation
- `failed`: Verification process encountered an error

### TriageVerdict
Prioritization decision:
- `pass`: True positive, should be fixed
- `kill`: False positive or noise, ignore
- `downgrade`: Theoretical impact only, includes `adjusted_severity`
- `chain_required`: Needs a partner finding to be exploitable, includes `chain_partner_ids`

### SecurityIssue
Extended security classification:
- `category`: Issue category (e.g., `injection`, `memory_corruption`)
- `cwe_id`: Optional CWE identifier
- `owasp_category`: Optional OWASP category label
- `mitre_attack`: Optional MITRE ATT&CK technique
- `custom_tags`: Additional user-defined tags

### Evidence
Supporting evidence item:
- `source`: Evidence source type (e.g., `semgrep`, `llm_analysis`, `independent_verifier`)
- `weight`: Confidence weight (0.0–1.0)
- `detail`: Detailed description of the evidence
- `timestamp`: UTC timestamp when evidence was collected

### VerificationTier
Evidence support level:
- `verified`: Evidence from ≥2 different source kinds, including at least one verifier
- `supported`: ≥2 evidence items of any kind, or single source with confidence > 0.8
- `unverified`: Single-source or no evidence

---

**See also:** [Output Interpretation Guide](output-interpretation.md) for human-readable guidance on acting on findings.
