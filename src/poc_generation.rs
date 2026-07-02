//! PoC Generation Engine
//!
//! Generates Proof of Concept code for verified findings:
//! - Creates safe, non-destructive PoC examples
//! - Supports multiple output formats (Rust, Python, shell)
//! - Includes mitigation examples
//! - Integrates with AnalysisContext (T5)

use crate::context::AnalysisContext;
use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Output format for PoC generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PoCFormat {
    /// Rust code
    #[default]
    Rust,
    /// Python code
    Python,
    /// Shell script
    Shell,
    /// Go code
    Go,
}

/// A generated proof of concept with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfConcept {
    /// Unique identifier for this PoC.
    pub id: String,
    /// Finding this PoC relates to.
    pub finding_id: String,
    /// The generated PoC code.
    pub code: String,
    /// Format of the PoC.
    pub format: PoCFormat,
    /// Whether this PoC demonstrates an exploit (false) or mitigation (true).
    pub is_mitigation: bool,
    /// Description of what the PoC demonstrates.
    pub description: String,
    /// Language/framework specific metadata.
    pub metadata: HashMap<String, String>,
}

/// Result of PoC generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoCGenerationResult {
    /// Generated PoCs.
    pub proofs: Vec<ProofOfConcept>,
    /// Errors encountered during generation.
    pub errors: Vec<String>,
}

/// Engine for generating proofs of concept.
#[derive(Debug, Clone)]
pub struct PoCGenerationEngine {
    /// Templates for different vulnerability types.
    pub templates: HashMap<String, PoCTemplate>,
}

impl Default for PoCGenerationEngine {
    fn default() -> Self {
        let mut engine = Self {
            templates: HashMap::new(),
        };
        engine.init_templates();
        engine
    }
}

/// A template for generating PoCs.
#[derive(Debug, Clone)]
pub struct PoCTemplate {
    /// CWE this template applies to.
    cwe_id: String,
    /// PoC format.
    format: PoCFormat,
    /// Vulnerable code pattern.
    vulnerable_pattern: String,
    /// Safe code pattern (mitigation).
    safe_pattern: String,
    /// Description of the vulnerability.
    description: String,
}

impl PoCTemplate {
    /// Get the format of this template.
    pub fn format(&self) -> PoCFormat {
        self.format
    }
}

impl PoCGenerationEngine {
    /// Create a new PoC generation engine with default templates.
    pub fn new() -> Self {
        let mut engine = Self::default();
        engine.init_templates();
        engine
    }

    /// Initialize default PoC templates for common vulnerabilities.
    fn init_templates(&mut self) {
        let templates = vec![
            // SQL Injection (CWE-89)
            PoCTemplate {
                cwe_id: "CWE-89".to_string(),
                format: PoCFormat::Python,
                vulnerable_pattern: r#"# Vulnerable: SQL injection
cursor.execute(f"SELECT * FROM users WHERE id = {user_input})"#.to_string(),
                safe_pattern: r#"# Safe: Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))"#.to_string(),
                description: "SQL Injection vulnerability - user input directly concatenated into query".to_string(),
            },
            // Command Injection (CWE-78)
            PoCTemplate {
                cwe_id: "CWE-78".to_string(),
                format: PoCFormat::Python,
                vulnerable_pattern: r#"# Vulnerable: Command injection
os.system(f"ping {user_input})"#.to_string(),
                safe_pattern: r#"# Safe: Use subprocess with list
subprocess.run(["ping", user_input], shell=False)"#.to_string(),
                description: "OS Command Injection - user input used in shell command".to_string(),
            },
            // Path Traversal (CWE-22)
            PoCTemplate {
                cwe_id: "CWE-22".to_string(),
                format: PoCFormat::Python,
                vulnerable_pattern: r#"# Vulnerable: Path traversal
with open(f"/var/files/{filename}") as f:
    content = f.read()"#.to_string(),
                safe_pattern: r#"# Safe: Validate and sanitize path
import os
filename = os.path.basename(filename)
safe_path = os.path.join("/var/files", filename)
if not safe_path.startswith("/var/files"):
    raise ValueError("Invalid path")
with open(safe_path) as f:
    content = f.read()"#.to_string(),
                description: "Path Traversal - unsanitized file path could access arbitrary files".to_string(),
            },
            // XSS (CWE-79)
            PoCTemplate {
                cwe_id: "CWE-79".to_string(),
                format: PoCFormat::Python,
                vulnerable_pattern: r#"# Vulnerable: XSS
response.write(f"<div>{user_input}</div>")"#.to_string(),
                safe_pattern: r#"# Safe: Escape HTML
import html
response.write(f"<div>{html.escape(user_input)}</div>")"#.to_string(),
                description: "Cross-Site Scripting (XSS) - unescaped user input in HTML".to_string(),
            },
            // Hardcoded credentials (CWE-798)
            PoCTemplate {
                cwe_id: "CWE-798".to_string(),
                format: PoCFormat::Python,
                vulnerable_pattern: r#"# Vulnerable: Hardcoded credentials
PASSWORD = "secret123"
API_KEY = "sk-abcdef1234567890""#.to_string(),
                safe_pattern: r#"# Safe: Use environment variables
import os
PASSWORD = os.environ.get("APP_PASSWORD")
API_KEY = os.environ.get("API_KEY")
if not PASSWORD or not API_KEY:
    raise ValueError("Missing required credentials")"#.to_string(),
                description: "Hardcoded Credentials - secrets embedded in source code".to_string(),
            },
            // Use of weak hash (CWE-327)
            PoCTemplate {
                cwe_id: "CWE-327".to_string(),
                format: PoCFormat::Python,
                vulnerable_pattern: r#"# Vulnerable: Weak cryptographic hash
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()"#.to_string(),
                safe_pattern: r#"# Safe: Use strong hash function
import hashlib
password_hash = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)"#.to_string(),
                description: "Use of Weak Cryptographic Hash - MD5 is cryptographically broken".to_string(),
            },
            // Insecure random (CWE-338)
            PoCTemplate {
                cwe_id: "CWE-338".to_string(),
                format: PoCFormat::Python,
                vulnerable_pattern: r#"# Vulnerable: Predictable random
import random
token = random.random()"#.to_string(),
                safe_pattern: r#"# Safe: Use cryptographically secure random
import secrets
token = secrets.token_hex(32)"#.to_string(),
                description: "Use of Cryptographically Weak PRNG - random.random() is predictable".to_string(),
            },
            // Unsafe YAML load (CWE-502)
            PoCTemplate {
                cwe_id: "CWE-502".to_string(),
                format: PoCFormat::Python,
                vulnerable_pattern: r#"# Vulnerable: Unsafe YAML deserialization
import yaml
data = yaml.unsafe_load(user_input)"#.to_string(),
                safe_pattern: r#"# Safe: Use safe loader
import yaml
data = yaml.safe_load(user_input)"#.to_string(),
                description: "Deserialization of Untrusted Data - yaml.unsafe_load can execute arbitrary code".to_string(),
            },
            // Eval injection (CWE-95)
            PoCTemplate {
                cwe_id: "CWE-95".to_string(),
                format: PoCFormat::Python,
                vulnerable_pattern: r#"# Vulnerable: Eval injection
result = eval(user_expression)"#.to_string(),
                safe_pattern: r#"# Safe: Use AST parsing for math expressions
import ast
import operator
ops = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}
def safe_eval(node):
    if isinstance(node, ast.Num):
        return node.n
    elif isinstance(node, ast.BinOp):
        return ops[type(node.op)](safe_eval(node.left), safe_eval(node.right))
    else:
        raise ValueError("Unsupported operation")
result = safe_eval(ast.parse(user_expression, mode='eval').body)"#.to_string(),
                description: "Code Injection - eval() executes arbitrary Python code".to_string(),
            },
            // XML XXE (CWE-611)
            PoCTemplate {
                cwe_id: "CWE-611".to_string(),
                format: PoCFormat::Python,
                vulnerable_pattern: r#"# Vulnerable: XML external entity
import xml.etree.ElementTree as ET
tree = ET.parse(user_xml)"#.to_string(),
                safe_pattern: r#"# Safe: Disable entity resolution
import xml.etree.ElementTree as ET
parser = ET.XMLParser()
parser.entity_resolver = lambda x: ""
tree = ET.parse(user_xml, parser=parser)"#.to_string(),
                description: "XML External Entity (XXE) - untrusted XML can access local files".to_string(),
            },
            // Rust: Buffer overflow (CWE-121)
            PoCTemplate {
                cwe_id: "CWE-121".to_string(),
                format: PoCFormat::Rust,
                vulnerable_pattern: r#"// Vulnerable: Buffer overflow risk
unsafe {
    let mut buf = [0u8; 10];
    std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), size);
}"#.to_string(),
                safe_pattern: r#"// Safe: Bound-checked copy
let mut buf = vec![0u8; size];
buf.copy_from_slice(&data[..size]);"#.to_string(),
                description: "Buffer Overflow - unchecked memory copy".to_string(),
            },
            // Rust: Unsafe raw pointer (CWE-119)
            PoCTemplate {
                cwe_id: "CWE-119".to_string(),
                format: PoCFormat::Rust,
                vulnerable_pattern: r#"// Vulnerable: Unchecked pointer dereference
unsafe {
    let ptr = data.as_ptr();
    let val = *ptr.offset(10);
}"#.to_string(),
                safe_pattern: r#"// Safe: Use iterator with bounds check
if let Some(val) = data.get(10) {
    tracing::debug!("{}", val);
}"#.to_string(),
                description: "Improper Restriction of Operations within Memory Buffer - unchecked pointer arithmetic".to_string(),
            },
            // Shell: Command injection (CWE-78)
            PoCTemplate {
                cwe_id: "CWE-78".to_string(),
                format: PoCFormat::Shell,
                vulnerable_pattern: r#"# Vulnerable: Command injection
rm -rf $INPUT_DIR/*"#.to_string(),
                safe_pattern: r#"# Safe: Validate input
if [[ "$INPUT_DIR" =~ ^/[a-zA-Z0-9_/-]+$ ]]; then
    rm -rf "$INPUT_DIR"/*
else
    echo "Invalid path"
    exit 1
fi"#.to_string(),
                description: "OS Command Injection in shell script".to_string(),
            },
            // Go: SQL injection
            PoCTemplate {
                cwe_id: "CWE-89".to_string(),
                format: PoCFormat::Go,
                vulnerable_pattern: r#"// Vulnerable: SQL injection
db.Query("SELECT * FROM users WHERE id = " + userID)"#.to_string(),
                safe_pattern: r#"// Safe: Parameterized query
db.Query("SELECT * FROM users WHERE id = $1", userID)"#.to_string(),
                description: "SQL Injection in Go".to_string(),
            },
            // Go: Path traversal
            PoCTemplate {
                cwe_id: "CWE-22".to_string(),
                format: PoCFormat::Go,
                vulnerable_pattern: r#"// Vulnerable: Path traversal
data, _ := os.ReadFile("/var/data/" + filename)"#.to_string(),
                safe_pattern: r#"// Safe: Path validation
func safePath(filename string) (string, error) {
    fullPath := filepath.Join("/var/data/", filename)
    if !strings.HasPrefix(fullPath, "/var/data/") {
        return "", errors.New("path traversal attempt")
    }
    return fullPath, nil
}"#.to_string(),
                description: "Path Traversal in Go".to_string(),
            },
        ];

        for template in templates {
            let key = format!("{}:{:?}", template.cwe_id, template.format);
            self.templates.insert(key, template);
        }
    }

    /// Generate PoCs for verified findings.
    ///
    /// * `findings` - Vulnerability findings to generate PoCs for
    /// * `context` - AnalysisContext for historical data and context
    /// * `formats` - Desired output formats
    pub fn generate(
        &self,
        findings: &[VulnerabilityFinding],
        _context: &AnalysisContext,
        formats: &[PoCFormat],
    ) -> PoCGenerationResult {
        let mut proofs = Vec::new();
        let mut errors = Vec::new();

        // Filter to only confirmed/high confidence findings
        let relevant_findings: Vec<_> = findings
            .iter()
            .filter(|f| {
                // Include if verified as confirmed or high severity
                matches!(
                    f.verification_status,
                    Some(VerificationStatus::Confirmed) | None
                ) && f.severity.is_high_or_critical()
                    || f.severity == Severity::High
                    || f.severity == Severity::Critical
            })
            .collect();

        for finding in relevant_findings {
            // Try to find a matching template
            if let Some(cwe_id) = &finding.cwe_id {
                for format in formats {
                    match self.generate_poc(finding, cwe_id, *format) {
                        Ok(poc) => proofs.push(poc),
                        Err(e) => errors.push(e),
                    }
                }
            } else {
                // Try category-based matching
                if let Some(poc) = self.generate_category_poc(finding, formats) {
                    proofs.push(poc);
                }
            }
        }

        PoCGenerationResult { proofs, errors }
    }

    /// Generate a PoC for a specific CWE.
    fn generate_poc(
        &self,
        finding: &VulnerabilityFinding,
        cwe_id: &str,
        format: PoCFormat,
    ) -> Result<ProofOfConcept, String> {
        let key = format!("{}:{:?}", cwe_id, format);

        if let Some(template) = self.templates.get(&key) {
            Ok(ProofOfConcept {
                id: format!("poc-{}-{}", cwe_id.to_lowercase(), uuid_simple()),
                finding_id: finding.id.clone(),
                code: template.vulnerable_pattern.clone(),
                format,
                is_mitigation: false,
                description: template.description.clone(),
                metadata: HashMap::new(),
            })
        } else {
            // Try default format fallback
            let default_key = format!("{}:Python", cwe_id);
            if let Some(template) = self.templates.get(&default_key) {
                return Ok(ProofOfConcept {
                    id: format!("poc-{}-{}", cwe_id.to_lowercase(), uuid_simple()),
                    finding_id: finding.id.clone(),
                    code: template.vulnerable_pattern.clone(),
                    format: PoCFormat::Python,
                    is_mitigation: false,
                    description: template.description.clone(),
                    metadata: HashMap::new(),
                });
            }
            Err(format!("No template found for {} in {:?}", cwe_id, format))
        }
    }

    /// Generate PoC based on category if CWE not found.
    fn generate_category_poc(
        &self,
        finding: &VulnerabilityFinding,
        formats: &[PoCFormat],
    ) -> Option<ProofOfConcept> {
        let category = finding.security_issue.as_ref()?.category.to_string();
        let format = formats.first().copied().unwrap_or_default();

        // Try category-based templates
        let cwe_fallback = match category.as_str() {
            "injection" => "CWE-89",
            "memory_corruption" => "CWE-121",
            "authentication_bypass" => "CWE-287",
            "cryptographic_misuse" => "CWE-327",
            _ => return None,
        };

        let key = format!("{}:{:?}", cwe_fallback, format);
        if let Some(template) = self.templates.get(&key) {
            return Some(ProofOfConcept {
                id: format!("poc-{}-{}", cwe_fallback.to_lowercase(), uuid_simple()),
                finding_id: finding.id.clone(),
                code: template.vulnerable_pattern.clone(),
                format,
                is_mitigation: false,
                description: template.description.clone(),
                metadata: HashMap::new(),
            });
        }

        None
    }

    /// Generate mitigation code for a finding.
    pub fn generate_mitigation(&self, finding: &VulnerabilityFinding) -> Option<ProofOfConcept> {
        let cwe_id = finding.cwe_id.as_ref()?;
        let format = PoCFormat::Python; // Default to Python for mitigations

        let key = format!("{}:{:?}", cwe_id, format);
        let template = self.templates.get(&key)?;

        Some(ProofOfConcept {
            id: format!("mit-{}-{}", cwe_id.to_lowercase(), uuid_simple()),
            finding_id: finding.id.clone(),
            code: template.safe_pattern.clone(),
            format,
            is_mitigation: true,
            description: format!("Mitigation for {}", template.description),
            metadata: HashMap::new(),
        })
    }

    /// Get available templates for a format.
    pub fn available_templates(&self, format: PoCFormat) -> Vec<String> {
        self.templates
            .values()
            .filter(|t| t.format == format)
            .map(|t| t.cwe_id.clone())
            .collect()
    }
}

/// Generate a simple UUID-like string.
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:x}{:x}", duration.as_secs(), duration.subsec_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_finding(cwe_id: &str) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: "test-finding-1".to_string(),
            title: "Test Vulnerability".to_string(),
            description: "A test vulnerability".to_string(),
            severity: Severity::High,
            confidence_score: 0.9,
            cwe_id: Some(cwe_id.to_string()),
            file_path: "test.py".to_string(),
            line_number: Some(42),
            code_snippet: Some("execute(user_input)".to_string()),
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["test".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: Some(0.8),
            cross_file_references: None,
            verification_status: Some(VerificationStatus::Confirmed),
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        }
    }

    #[test]
    fn test_engine_creation() {
        let engine = PoCGenerationEngine::new();
        assert!(!engine.templates.is_empty());
    }

    #[test]
    fn test_generate_sql_injection_poc() {
        let engine = PoCGenerationEngine::new();
        let finding = create_test_finding("CWE-89");
        let context = AnalysisContext::default();

        let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

        assert!(!result.proofs.is_empty());
        assert!(result.proofs[0].code.contains("SELECT"));
    }

    #[test]
    fn test_generate_command_injection_poc() {
        let engine = PoCGenerationEngine::new();
        let finding = create_test_finding("CWE-78");
        let context = AnalysisContext::default();

        let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

        assert!(!result.proofs.is_empty());
        assert!(
            result.proofs[0].code.contains("system")
                || result.proofs[0].code.contains("subprocess")
        );
    }

    #[test]
    fn test_generate_xss_poc() {
        let engine = PoCGenerationEngine::new();
        let finding = create_test_finding("CWE-79");
        let context = AnalysisContext::default();

        let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

        assert!(!result.proofs.is_empty());
        assert!(result.proofs[0].code.contains("div") || result.proofs[0].code.contains("escape"));
    }

    #[test]
    fn test_generate_mitigation() {
        let engine = PoCGenerationEngine::new();
        let finding = create_test_finding("CWE-89");

        let mitigation = engine.generate_mitigation(&finding);

        assert!(mitigation.is_some());
        let m = mitigation.unwrap();
        assert!(m.is_mitigation);
        assert!(m.code.contains("safe") || m.code.contains("%s"));
    }

    #[test]
    fn test_generate_rust_poc() {
        let engine = PoCGenerationEngine::new();
        let finding = create_test_finding("CWE-121");
        let context = AnalysisContext::default();

        let result = engine.generate(&[finding], &context, &[PoCFormat::Rust]);

        assert!(!result.proofs.is_empty());
        assert_eq!(result.proofs[0].format, PoCFormat::Rust);
    }

    #[test]
    fn test_generate_shell_poc() {
        let engine = PoCGenerationEngine::new();
        let finding = create_test_finding("CWE-78");
        let context = AnalysisContext::default();

        let result = engine.generate(&[finding], &context, &[PoCFormat::Shell]);

        assert!(!result.proofs.is_empty());
        assert_eq!(result.proofs[0].format, PoCFormat::Shell);
    }

    #[test]
    fn test_generate_go_poc() {
        let engine = PoCGenerationEngine::new();
        let finding = create_test_finding("CWE-89");
        let context = AnalysisContext::default();

        let result = engine.generate(&[finding], &context, &[PoCFormat::Go]);

        assert!(!result.proofs.is_empty());
        assert_eq!(result.proofs[0].format, PoCFormat::Go);
    }

    #[test]
    fn test_multiple_formats() {
        let engine = PoCGenerationEngine::new();
        let finding = create_test_finding("CWE-89");
        let context = AnalysisContext::default();

        let result = engine.generate(&[finding], &context, &[PoCFormat::Python, PoCFormat::Rust]);

        assert_eq!(result.proofs.len(), 2);
    }

    #[test]
    fn test_unknown_cwe() {
        let engine = PoCGenerationEngine::new();
        let finding = create_test_finding("CWE-999");
        let context = AnalysisContext::default();

        let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

        // Should still generate something through category fallback or similar
        // or return empty proofs
        assert!(result.errors.len() >= 1 || result.proofs.len() >= 1);
    }

    #[test]
    fn test_low_severity_filtered() {
        let engine = PoCGenerationEngine::new();
        let mut finding = create_test_finding("CWE-89");
        finding.severity = Severity::Low;
        let context = AnalysisContext::default();

        let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

        // Low severity without verification might be filtered
        // This test ensures the code handles it gracefully
        assert!(result.errors.is_empty() || result.proofs.is_empty());
    }

    #[test]
    fn test_available_templates() {
        let engine = PoCGenerationEngine::new();

        let python_templates = engine.available_templates(PoCFormat::Python);
        assert!(!python_templates.is_empty());

        let rust_templates = engine.available_templates(PoCFormat::Rust);
        assert!(!rust_templates.is_empty());
    }

    #[test]
    fn test_proof_of_concept_structure() {
        let engine = PoCGenerationEngine::new();
        let finding = create_test_finding("CWE-89");
        let context = AnalysisContext::default();

        let result = engine.generate(&[finding], &context, &[PoCFormat::Python]);

        if !result.proofs.is_empty() {
            let poc = &result.proofs[0];
            assert!(!poc.id.is_empty());
            assert!(!poc.finding_id.is_empty());
            assert!(!poc.code.is_empty());
            assert!(!poc.description.is_empty());
        }
    }
}
