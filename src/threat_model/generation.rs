//! Threat model generation logic.
//!
//! Implements STRIDE-based threat model generation with static analysis
//! and LLM-assisted modes.

use crate::analysis_context::AnalysisContext;
use crate::project_type::detect_project_type;
use std::path::Path;

/// Generate threat model using static analysis fallback (no LLM).
#[cfg_attr(test, visibility::make(pub))]
pub fn generate_threat_model_static(architecture: &str) -> String {
    let mut threat_model = String::from("=== THREAT MODEL: STRIDE Analysis ===\n\n");

    // Parse architecture for key components (check for negations first)
    let no_db = architecture.contains("No database")
        || architecture.contains("no database")
        || architecture.contains("No DB")
        || architecture.contains("no DB");
    let no_filesys = architecture.contains("No file system")
        || architecture.contains("no file system")
        || architecture.contains("No filesystem")
        || architecture.contains("no filesystem");

    let has_db = !no_db
        && (architecture.contains("database")
            || architecture.contains("data store")
            || architecture.contains("sqlite")
            || architecture.contains("postgres")
            || architecture.contains("mysql"));
    let has_api = architecture.contains("HTTP")
        || architecture.contains("endpoint")
        || architecture.contains("API")
        || architecture.contains("router");
    let has_filesys = !no_filesys
        && (architecture.contains("file system")
            || architecture.contains("filesystem")
            || architecture.contains("file access")
            || architecture.contains("file upload"));

    threat_model.push_str("### 1. TRUST BOUNDARIES\n");
    if has_db {
        threat_model.push_str("External -> API Gateway -> Application Logic -> Data Store(s)\n\n");
    } else {
        threat_model.push_str("External -> API Gateway -> Application Logic\n\n");
    }

    if has_api {
        threat_model
            .push_str("- **External Interface**: HTTP/HTTPS API (trust boundary: untrusted)\n");
        threat_model.push_str("  - Entry points: All HTTP endpoints\n");
        threat_model.push_str("  - Risks: Request forgery, header injection, SSRF\n\n");
    }

    if has_db {
        threat_model
            .push_str("- **Data Store**: Database connection (trust boundary: sensitive)\n");
        threat_model.push_str("  - Access: Application service layer\n");
        threat_model
            .push_str("  - Risks: SQL injection, privilege escalation, data exfiltration\n\n");
    }

    if has_filesys {
        threat_model.push_str("- **File System**: Local storage (trust boundary: medium)\n");
        threat_model.push_str("  - Access: File upload, configuration loading\n");
        threat_model.push_str(
            "  - Risks: Path traversal, arbitrary file read/write, supply chain attacks\n\n",
        );
    }

    threat_model.push_str("### 2. DATA FLOWS\n");
    if has_api {
        threat_model.push_str("- User Request -> API Endpoint -> Validation -> Business Logic -> Data Store -> Response\n");
        threat_model.push_str("  - Sensitive in transit: Consider TLS enforcement\n");
        threat_model.push_str("  - Sensitive at rest: Consider encryption, access controls\n\n");
    }

    if has_db {
        threat_model.push_str("- Application Write -> Database (authentication required)\n");
        threat_model.push_str("  - Sensitive data: PII, credentials, session tokens\n");
        threat_model
            .push_str("  - Risks: Unauthorized access, data leakage, integrity compromise\n\n");
    }

    threat_model.push_str("### 3. ATTACK SURFACES\n");
    threat_model.push_str("- **HTTP Endpoints**: All routes are potential entry points\n");
    if has_filesys {
        threat_model.push_str("- **File System**: Upload directories, config files, temp files\n");
    }
    if has_db {
        threat_model.push_str("- **Database**: Direct access points, backup exposure\n");
    }
    threat_model.push_str("### 4. STRIDE THREATS\n\n");

    threat_model.push_str("#### S - Spoofing\n");
    threat_model.push_str("- Authentication bypass via session token manipulation\n");
    if has_api {
        threat_model.push_str("- API key forgery, rate limiting circumvention\n");
    }
    threat_model
        .push_str("**Recommendation**: Implement strong auth, CSRF protection, rate limiting\n\n");

    threat_model.push_str("#### T - Tampering\n");
    threat_model.push_str("- Input validation bypass leading to injection attacks\n");
    if has_db {
        threat_model.push_str("- SQL injection via unvalidated parameters\n");
    }
    if has_filesys {
        threat_model.push_str("- Path traversal in file operations\n");
    }
    threat_model
        .push_str("**Recommendation**: Input sanitization, parameterized queries, allowlists\n\n");

    threat_model.push_str("#### R - Repudiation\n");
    threat_model.push_str("- Lack of audit logging prevents activity attribution\n");
    threat_model.push_str("- Session tokens not bound to user identity\n");
    threat_model.push_str("**Recommendation**: Comprehensive logging, immutable audit trails\n\n");

    threat_model.push_str("#### I - Information Disclosure\n");
    threat_model.push_str("- Sensitive data in logs or error messages\n");
    threat_model.push_str("- Insecure storage of credentials or tokens\n");
    if has_filesys {
        threat_model.push_str("- Config files with secrets on disk\n");
    }
    threat_model
        .push_str("**Recommendation**: Log sanitization, secure storage, encryption at rest\n\n");

    threat_model.push_str("#### D - Denial of Service\n");
    threat_model.push_str("- Resource exhaustion via unlimited request processing\n");
    if has_api {
        threat_model.push_str("- API endpoint overload without rate limiting\n");
    }
    if has_filesys {
        threat_model.push_str("- Disk fill via unbounded file uploads\n");
    }
    threat_model
        .push_str("**Recommendation**: Rate limiting, connection limits, resource quotas\n\n");

    threat_model.push_str("#### E - Elevation of Privilege\n");
    threat_model.push_str("- Insufficient authorization checks in business logic\n");
    threat_model.push_str("- Vertical privilege escalation via role manipulation\n");
    threat_model.push_str("- Horizontal privilege escalation via data access bypass\n");
    threat_model.push_str("**Recommendation**: Role-based access control, least privilege, authorization middleware\n");

    threat_model
}

/// Save threat model to AnalysisContext.
#[cfg_attr(test, visibility::make(pub))]
pub fn save_to_context(target_path: &Path, threat_model: &str) {
    let mut ctx = AnalysisContext::load(target_path).unwrap_or_else(|_| AnalysisContext::default());
    ctx.threat_model = Some(threat_model.to_string());
    ctx.save(target_path)
        .expect("Failed to save threat model to context");
}

/// Load architecture summary from AnalysisContext or regenerate via CodebaseUnderstanding.
#[cfg_attr(test, visibility::make(pub))]
pub fn load_or_generate_architecture(_target_path: &Path, context: &AnalysisContext) -> String {
    if !context.architecture_summary.is_empty() {
        tracing::debug!("Using existing architecture summary from context");
        context.architecture_summary.clone()
    } else {
        tracing::warn!("No architecture summary in context, using empty architecture");
        "No architecture summary available".to_string()
    }
}

/// Generate threat model using LLM with full STRIDE analysis.
pub async fn generate_threat_model_with_llm(
    target_path: &Path,
    architecture: &str,
    client: &crate::llm::LlmClient,
) -> Result<String, String> {
    let project_type = detect_project_type(target_path);

    let prompt = format!(
        r#"You are a senior security engineer performing a STRIDE threat model.
        
PROJECT TYPE: {project_type}
PROJECT PATH: {target_path}

ARCHITECTURE SUMMARY:
{architecture}

Generate a comprehensive STRIDE threat model including:
1. TRUST BOUNDARIES: External vs internal systems, user trust levels, component isolation
2. DATA FLOWS: Request/response cycles, persistence points, sensitive data transit/storage
3. ATTACK SURFACES: HTTP endpoints, file system access, database connections, plugin interfaces
4. STRIDE THREATS:
   - SPOOFING: Impersonation risks, authentication bypass, session hijacking
   - TAMPERING: Injection, deserialization, data integrity
   - REPUTATION: Log tampering, non-repudiation, audit trail integrity
   - INFORMATION DISCLOSURE: Sensitive data exposure, insecure storage, data leakage
   - DENIAL OF SERVICE: Resource exhaustion, DoS attack vectors, availability impacts
   - ELEVATION OF PRIVILEGE: Privilege escalation, authorization bypass, vertical/horizontal privilege creep

For each threat:
- Impact: Low/Medium/High/Critical
- Likelihood: Low/Medium/High/Critical
- Recommendation: Specific mitigation strategy

Output as structured markdown with clear threat categorization.
"#,
        target_path = target_path.display(),
        project_type = project_type,
    );

    let messages = vec![crate::llm::ChatMessage::system(&prompt)];

    match client.chat(&messages).await {
        Ok(response_with_model) => {
            tracing::debug!(
                "Threat model LLM response length: {} bytes",
                response_with_model.content.len()
            );
            Ok(response_with_model.content)
        }
        Err(e) => {
            tracing::warn!(
                "LLM threat modeling failed: {}. Using static analysis fallback.",
                e
            );
            Ok(generate_threat_model_static(architecture))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_threat_model_static_basic() {
        let architecture = "A simple web app with database";
        let tm = generate_threat_model_static(architecture);

        assert!(tm.contains("TRUST BOUNDARIES"));
        assert!(tm.contains("DATA FLOWS"));
        assert!(tm.contains("STRIDE THREATS"));
    }

    #[test]
    fn test_generate_threat_model_static_no_db() {
        let architecture = "No database, just static files";
        let tm = generate_threat_model_static(architecture);

        assert!(!tm.contains("Data Store"));
        assert!(tm.contains("TRUST BOUNDARIES"));
    }

    #[test]
    fn test_generate_threat_model_static_with_api() {
        let architecture = "HTTP API with endpoints";
        let tm = generate_threat_model_static(architecture);

        assert!(tm.contains("HTTP Endpoints"));
        assert!(tm.contains("External Interface"));
    }

    #[test]
    fn test_save_to_context() {
        use tempfile::tempdir;
        let tmp = tempdir().unwrap();

        let tm = "Test threat model";
        save_to_context(tmp.path(), tm);

        let ctx = AnalysisContext::load(tmp.path()).unwrap();
        assert_eq!(ctx.threat_model, Some(tm.to_string()));
    }

    #[test]
    fn test_load_or_generate_architecture_with_summary() {
        use tempfile::tempdir;
        let tmp = tempdir().unwrap();

        let mut ctx = AnalysisContext::default();
        ctx.architecture_summary = "Test architecture".to_string();
        ctx.save(tmp.path()).unwrap();

        let loaded = AnalysisContext::load(tmp.path()).unwrap();
        let arch = load_or_generate_architecture(tmp.path(), &loaded);
        assert_eq!(arch, "Test architecture");
    }

    #[test]
    fn test_load_or_generate_architecture_empty() {
        use tempfile::tempdir;
        let tmp = tempdir().unwrap();

        let ctx = AnalysisContext::default();
        let arch = load_or_generate_architecture(tmp.path(), &ctx);
        assert_eq!(arch, "No architecture summary available");
    }
}
