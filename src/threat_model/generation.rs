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

    let lower = architecture.to_lowercase();
    let no_db = lower.contains("no database") || lower.contains("no db");
    let no_filesys = lower.contains("no file system") || lower.contains("no filesystem");

    let has_db = !no_db
        && (lower.contains("database")
            || lower.contains("data store")
            || lower.contains("sqlite")
            || lower.contains("postgres")
            || lower.contains("mysql"));
    let has_api = lower.contains("http")
        || lower.contains("endpoint")
        || lower.contains("api")
        || lower.contains("router");
    let has_filesys = !no_filesys
        && (lower.contains("file system")
            || lower.contains("filesystem")
            || lower.contains("file access")
            || lower.contains("file upload"));

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

/// Generate architecture summary by statically inspecting the codebase.
#[cfg_attr(test, visibility::make(pub))]
pub fn generate_architecture_static(target_path: &Path) -> String {
    let mut summary = String::new();

    // Get project type
    let project_type = detect_project_type(target_path);
    summary.push_str("=== ARCHITECTURAL SUMMARY ===\n");
    summary.push_str(&format!("Project type: {}\n", project_type));

    // Index project files
    let file_index = crate::indexer::FileIndex::index_project(
        target_path.to_str().unwrap_or("."),
        &[
            "rust".to_string(),
            "typescript".to_string(),
            "javascript".to_string(),
            "python".to_string(),
        ],
        1024 * 1024, // 1MB max file size
        &[
            "target/".to_string(),
            "node_modules/".to_string(),
            ".git/".to_string(),
        ],
        true, // enable_file_filtering
    );

    let file_count = file_index.as_ref().map(|i| i.files.len()).unwrap_or(0);
    summary.push_str(&format!("Total files: {}\n\n", file_count));

    // Detect components by scanning file contents
    let (has_http, has_db, has_filesys, has_auth) = detect_components(target_path, file_index);

    summary.push_str("Components detected:\n");
    if has_http {
        summary.push_str("- HTTP API: yes\n");
    } else {
        summary.push_str("- No web framework\n");
    }
    if has_db {
        summary.push_str("- database: yes\n");
    } else {
        summary.push_str("- No database\n");
    }
    if has_filesys {
        summary.push_str("- file system: yes\n");
    } else {
        summary.push_str("- No file system\n");
    }
    if has_auth {
        summary.push_str("- Authentication: yes\n");
    } else {
        summary.push_str("- No auth\n");
    }
    summary.push('\n');

    // Entry points
    summary.push_str("Entry points:\n");
    if has_http {
        summary.push_str("- HTTP endpoints\n");
    }
    if file_count > 0 {
        summary.push_str("- Source code entry (main.rs / index.js / etc.)\n");
    }

    // Data stores
    summary.push_str("\nData stores:\n");
    if !has_db {
        summary.push_str("- None detected\n");
    }

    summary
}

/// Detect components by scanning indexed files for keywords.
fn detect_components(
    target_path: &Path,
    file_index: Result<crate::indexer::FileIndex, std::io::Error>,
) -> (bool, bool, bool, bool) {
    let mut has_http = false;
    let mut has_db = false;
    let mut has_filesys = false;
    let mut has_auth = false;

    let http_keywords = [
        "HTTP",
        "endpoint",
        "router",
        "axum",
        "actix",
        "warp",
        "rocket",
        "tower",
        "express",
        "flask",
        "django",
        "fastapi",
        "spring",
        "gin",
        "echo",
        "http::",
        "actix_web",
        "axum::",
    ];
    let db_keywords = [
        "sqlite",
        "postgres",
        "mysql",
        "mongodb",
        "redis",
        "database",
        "data store",
        "Repository",
        "Entity",
        "migration",
        "sqlx",
        "diesel",
        "orm",
        "prisma",
    ];
    let fs_keywords = [
        "fs::read",
        "fs::write",
        "File::open",
        "File::create",
        "tempfile",
        "file upload",
        "filesystem",
        "std::fs",
        "read_to_string",
    ];
    let auth_keywords = [
        "auth",
        "session",
        "token",
        "jwt",
        "password",
        "credential",
        "oauth",
        "bearer",
        "authentication",
        "authorization",
    ];

    // Get files from index or fallback to scanning common source files
    let files_to_scan = match file_index {
        Ok(index) => index.files.into_iter().take(100).collect(),
        Err(_) => {
            // Fallback: scan common source files directly
            let mut files = Vec::new();
            let src_path = target_path.join("src");
            if src_path.exists() {
                if let Ok(entries) = std::fs::read_dir(&src_path) {
                    for entry in entries.flatten().take(100) {
                        if entry.path().extension().and_then(|e| e.to_str()) == Some("rs") {
                            files.push(crate::indexer::FileInfo {
                                path: entry.path(),
                                size: 0,
                                language: "rust".to_string(),
                                hash: None,
                            });
                        }
                    }
                }
            }
            files
        }
    };

    for file_info in files_to_scan {
        if let Ok(content) = std::fs::read_to_string(&file_info.path) {
            let lower = content.to_lowercase();

            if !has_http
                && http_keywords
                    .iter()
                    .any(|k| lower.contains(&k.to_lowercase()))
            {
                has_http = true;
            }
            if !has_db
                && db_keywords
                    .iter()
                    .any(|k| lower.contains(&k.to_lowercase()))
            {
                has_db = true;
            }
            if !has_filesys
                && fs_keywords
                    .iter()
                    .any(|k| lower.contains(&k.to_lowercase()))
            {
                has_filesys = true;
            }
            if !has_auth
                && auth_keywords
                    .iter()
                    .any(|k| lower.contains(&k.to_lowercase()))
            {
                has_auth = true;
            }

            // Early exit if all detected
            if has_http && has_db && has_filesys && has_auth {
                break;
            }
        }
    }

    (has_http, has_db, has_filesys, has_auth)
}

/// Load architecture summary from AnalysisContext or regenerate via static codebase analysis.
#[cfg_attr(test, visibility::make(pub))]
pub fn load_or_generate_architecture(target_path: &Path, context: &AnalysisContext) -> String {
    if !context.architecture_summary.is_empty() {
        tracing::debug!("Using existing architecture summary from context");
        context.architecture_summary.clone()
    } else {
        tracing::info!("Generating architecture summary via static analysis");
        let generated = generate_architecture_static(target_path);
        // Persist for reuse by later phases
        let mut ctx =
            AnalysisContext::load(target_path).unwrap_or_else(|_| AnalysisContext::default());
        ctx.architecture_summary = generated.clone();
        if let Err(e) = ctx.save(target_path) {
            tracing::warn!("Failed to persist architecture summary: {e}");
        }
        generated
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
