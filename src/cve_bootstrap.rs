//! CVE Bootstrap Module
//!
//! Detects project stack and fetches relevant CVEs for threat intelligence.
//! Uses CveClient for fetching CVE data from CISA KEV and NVD.

use crate::cve_client::CveClient;
use crate::scanner_types::cve::{CveCluster, CveEntry};
use crate::scanner_types::project::{Dependency, DependencyEcosystem, ProjectStack};
use crate::scanner_types::severity::V3Severity;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use thiserror::Error;
use tracing::warn;

#[derive(Error, Debug)]
pub enum CveBootstrapError {
    #[error("Project detection error: {0}")]
    DetectionError(String),
    #[error("CVE fetch error: {0}")]
    FetchError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CveBootstrapError>;

/// Read a manifest file, returning None if it doesn't exist.
///
/// Centralizes the pattern each manifest parser repeated:
/// ```text
/// let path = root.join(name);
/// if !path.exists() { return Ok(None); }
/// let content = fs::read_to_string(&path)?;
/// ```
fn read_manifest(root: &Path, name: &str) -> Result<Option<String>> {
    let path = root.join(name);
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)?;
    Ok(Some(content))
}

pub struct CveBootstrapper {
    project_root: String,
    client: CveClient,
    cpe_hint: Option<String>,
}

/// How deep the language probe walks.
///
/// Shallow on purpose: this runs before indexing and only needs to answer
/// "is there PHP here", not to inventory the tree. Indexing does the full job.
const MAX_STACK_SCAN_DEPTH: usize = 3;

fn has_source_file(root: &Path, extensions: &[&str], max_depth: usize) -> bool {
    let mut dirs = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = dirs.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if path.is_dir() {
                // node_modules and vendor hold other languages' files and are
                // frequently the bulk of the tree.
                if depth < max_depth && !matches!(name.as_str(), "node_modules" | "vendor" | ".git")
                {
                    dirs.push((path, depth + 1));
                }
                continue;
            }
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if extensions.contains(&ext.to_lowercase().as_str()) {
                    return true;
                }
            }
        }
    }
    false
}

impl CveBootstrapper {
    pub fn new(project_root: String) -> Self {
        Self {
            project_root,
            client: CveClient::new(),
            cpe_hint: None,
        }
    }

    /// Create a new bootstrapper with an optional CPE hint for CVE filtering
    pub fn with_cpe_hint(project_root: String, cpe_hint: Option<String>) -> Self {
        Self {
            project_root,
            client: CveClient::new(),
            cpe_hint,
        }
    }

    /// Detect the project stack (languages, frameworks, dependencies)
    pub fn detect_project_stack(&self) -> Result<ProjectStack> {
        let mut stack = ProjectStack::default();

        let root = Path::new(&self.project_root);

        if root.join("Cargo.toml").exists() {
            if let Ok(cargo) = self.parse_cargo_toml(root) {
                stack.languages.push("Rust".to_string());
                stack.dependencies = cargo;
            }
        }

        if root.join("package.json").exists() {
            if let Ok(npm) = self.parse_package_json(root) {
                if !stack.languages.contains(&"JavaScript".to_string()) {
                    stack.languages.push("JavaScript".to_string());
                }
                stack.frameworks.extend(npm.0);
                for dep in npm.1 {
                    stack.dependencies.push(dep);
                }
            }
        }

        if root.join("requirements.txt").exists() {
            if let Ok(python) = self.parse_requirements_txt(root) {
                if !stack.languages.contains(&"Python".to_string()) {
                    stack.languages.push("Python".to_string());
                }
                stack.dependencies.extend(python);
            }
        }

        if root.join("go.mod").exists() {
            if let Ok(go) = self.parse_go_mod(root) {
                if !stack.languages.contains(&"Go".to_string()) {
                    stack.languages.push("Go".to_string());
                }
                stack.dependencies = go;
            }
        }

        if root.join("composer.json").exists() {
            if let Ok(composer) = self.parse_composer_json(root) {
                if !stack.languages.contains(&"PHP".to_string()) {
                    stack.languages.push("PHP".to_string());
                }
                stack.frameworks.extend(composer.0);
                for dep in composer.1 {
                    stack.dependencies.push(dep);
                }
            }
        }

        // A plugin usually has no composer.json -- WordPress core is not a
        // dependency, it is the host -- so the language is detected from the
        // source files themselves. Without this a PHP target got an empty
        // stack, and because the result was Ok nothing downstream could tell
        // "not PHP" from "found nothing".
        if has_source_file(root, &["php", "phtml", "php5", "inc"], MAX_STACK_SCAN_DEPTH)
            && !stack.languages.contains(&"PHP".to_string())
        {
            stack.languages.push("PHP".to_string());
        }

        // The directory shape is the reliable WordPress signal, and it is what
        // tells the discovery prompt this is WordPress.
        if (root.join("wp-includes").is_dir() || root.join("wp-content").is_dir())
            && !stack.frameworks.iter().any(|f| f == "WordPress")
        {
            stack.frameworks.push("WordPress".to_string());
        }

        Ok(stack)
    }

    /// Parse composer.json.
    pub fn parse_composer_json(&self, root: &Path) -> Result<(Vec<String>, Vec<Dependency>)> {
        let Some(content) = read_manifest(root, "composer.json")? else {
            return Ok((Vec::new(), Vec::new()));
        };
        let parsed: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| CveBootstrapError::DetectionError(e.to_string()))?;
        let require = parsed.get("require").and_then(|r| r.as_object());

        let mut deps = Vec::new();
        let mut frameworks = Vec::new();
        if let Some(require) = require {
            for (name, constraint) in require {
                // The PHP runtime itself is not a package with advisories.
                if name.eq_ignore_ascii_case("php") {
                    continue;
                }
                if let Some(version) = constraint.as_str() {
                    if name.starts_with("laravel/") && !frameworks.iter().any(|f| f == "Laravel") {
                        frameworks.push("Laravel".to_string());
                    }
                    if name.starts_with("symfony/") && !frameworks.iter().any(|f| f == "Symfony") {
                        frameworks.push("Symfony".to_string());
                    }
                    deps.push(Dependency {
                        name: name.clone(),
                        version: version.to_string(),
                        ecosystem: DependencyEcosystem::Packagist,
                    });
                }
            }
        }

        Ok((frameworks, deps))
    }

    pub fn parse_cargo_toml(&self, root: &Path) -> Result<Vec<Dependency>> {
        let Some(content) = read_manifest(root, "Cargo.toml")? else {
            return Ok(Vec::new());
        };
        let mut deps = Vec::new();

        let mut in_dependencies = false;
        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed == "[dependencies]" || trimmed == "[dev-dependencies]" {
                in_dependencies = true;
                continue;
            }

            if trimmed.starts_with('[') {
                in_dependencies = false;
                continue;
            }

            if in_dependencies && trimmed.contains('=') {
                let name = trimmed.split('=').next().unwrap_or("").trim().to_string();
                if !name.is_empty() && !name.starts_with('#') {
                    let version = trimmed
                        .split('=')
                        .nth(1)
                        .unwrap_or("")
                        .trim()
                        .trim_matches('"')
                        .to_string();

                    deps.push(Dependency {
                        name,
                        version,
                        ecosystem: DependencyEcosystem::CratesIo,
                    });
                }
            }
        }

        Ok(deps)
    }

    pub fn parse_package_json(&self, root: &Path) -> Result<(Vec<String>, Vec<Dependency>)> {
        let Some(content) = read_manifest(root, "package.json")? else {
            return Ok((Vec::new(), Vec::new()));
        };
        let mut frameworks = Vec::new();
        let mut deps = Vec::new();

        let json: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| CveBootstrapError::DetectionError(e.to_string()))?;

        if let Some(obj) = json.as_object() {
            if let Some(deps_obj) = obj.get("dependencies").and_then(|v| v.as_object()) {
                for (name, ver) in deps_obj {
                    let version = ver.as_str().unwrap_or("*").to_string();
                    deps.push(Dependency {
                        name: name.clone(),
                        version,
                        ecosystem: DependencyEcosystem::Npm,
                    });

                    if name == "react" {
                        frameworks.push("React".to_string());
                    } else if name == "vue" {
                        frameworks.push("Vue".to_string());
                    } else if name == "angular" || name == "@angular/core" {
                        frameworks.push("Angular".to_string());
                    } else if name == "express" {
                        frameworks.push("Express".to_string());
                    } else if name == "next" {
                        frameworks.push("Next.js".to_string());
                    }
                }
            }
        }

        Ok((frameworks, deps))
    }

    pub fn parse_requirements_txt(&self, root: &Path) -> Result<Vec<Dependency>> {
        let Some(content) = read_manifest(root, "requirements.txt")? else {
            return Ok(Vec::new());
        };
        let mut deps = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split("==").collect();
            let name = parts[0].trim().to_string();
            let version = parts
                .get(1)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "*".to_string());

            if !name.is_empty() {
                deps.push(Dependency {
                    name,
                    version,
                    ecosystem: DependencyEcosystem::PyPi,
                });
            }
        }

        Ok(deps)
    }

    /// Parse a dependency line and add to the dependencies list
    fn parse_dependency_line(
        line: &str,
        deps: &mut Vec<Dependency>,
        ecosystem: DependencyEcosystem,
    ) {
        let parts: Vec<&str> = line.split(' ').collect();
        if let Some(name) = parts.first() {
            let version = parts
                .get(1)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "*".to_string());
            deps.push(Dependency {
                name: name.to_string(),
                version,
                ecosystem,
            });
        }
    }

    pub fn parse_go_mod(&self, root: &Path) -> Result<Vec<Dependency>> {
        let Some(content) = read_manifest(root, "go.mod")? else {
            return Ok(Vec::new());
        };
        let mut deps = Vec::new();

        let mut in_require = false;
        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("require (") {
                in_require = true;
                continue;
            }

            if trimmed == ")" {
                in_require = false;
                continue;
            }

            if let Some(stripped) = trimmed.strip_prefix("require ") {
                Self::parse_dependency_line(stripped, &mut deps, DependencyEcosystem::GoModules);
                continue;
            }

            if in_require && !trimmed.is_empty() {
                Self::parse_dependency_line(trimmed, &mut deps, DependencyEcosystem::GoModules);
            }
        }

        Ok(deps)
    }

    /// Fetch relevant CVEs for the detected project stack
    pub async fn fetch_relevant_cves(&self, stack: &ProjectStack) -> Result<Vec<CveEntry>> {
        let mut all_cves = Vec::new();

        // If CPE hint is set, use it for CVE matching
        if let Some(cpe) = &self.cpe_hint {
            // Parse CPE format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
            let parts: Vec<&str> = cpe.split(':').collect();
            if parts.len() >= 5 {
                let vendor = parts[3];
                let product = parts[4];

                match self.client.fetch_nvd_cves(vendor, product).await {
                    Ok(cves) => all_cves.extend(cves),
                    Err(e) => {
                        warn!("Failed to fetch CVEs for CPE {}: {}", cpe, e);
                    }
                }
            }
        }

        // Also fetch CVEs based on dependency name matching
        for dep in &stack.dependencies {
            let parts: Vec<&str> = dep.name.split('/').collect();
            let (vendor, product) = if parts.len() >= 2 {
                (parts[0].to_string(), parts[1].to_string())
            } else {
                let name = dep.name.split('-').next().unwrap_or(&dep.name).to_string();
                (name, dep.name.clone())
            };

            match self.client.fetch_nvd_cves(&vendor, &product).await {
                Ok(cves) => all_cves.extend(cves),
                Err(e) => {
                    warn!("Failed to fetch CVEs for {}: {}", dep.name, e);
                }
            }
        }

        // Also try to fetch KEV catalog
        match self.client.fetch_kev_catalog().await {
            Ok(kev_cves) => all_cves.extend(kev_cves),
            Err(e) => {
                warn!("Failed to fetch KEV catalog: {}", e);
            }
        }

        // Deduplicate
        let mut seen = std::collections::HashSet::new();
        all_cves.retain(|cve| seen.insert(cve.cve_id.clone()));

        Ok(all_cves)
    }

    /// Cluster CVEs by vulnerability pattern
    pub fn cluster_by_pattern(cves: &[CveEntry]) -> Vec<CveCluster> {
        let mut pattern_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut dep_map: HashMap<String, Vec<String>> = HashMap::new();

        for cve in cves {
            let pattern = Self::classify_cve_pattern(cve);

            pattern_map
                .entry(pattern.clone())
                .or_default()
                .push(cve.cve_id.clone());
            dep_map.entry(pattern).or_default().push(cve.cve_id.clone());
        }

        let mut clusters = Vec::new();

        for (pattern_name, cve_ids) in pattern_map {
            let deps: Vec<String> = dep_map
                .get(&pattern_name)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(5)
                .collect();

            clusters.push(CveCluster {
                pattern_name,
                cve_count: cve_ids.len() as u32,
                example_cves: cve_ids.into_iter().take(5).collect(),
                affected_dependencies: deps,
            });
        }

        clusters.sort_by(|a, b| {
            b.cve_count
                .cmp(&a.cve_count)
                .then_with(|| a.pattern_name.cmp(&b.pattern_name))
        });

        clusters
    }

    fn classify_cve_pattern(cve: &CveEntry) -> String {
        let desc = cve.description.to_lowercase();

        if desc.contains("sql injection") || desc.contains("sql injection") {
            "SQL Injection".to_string()
        } else if desc.contains("xss") || desc.contains("cross-site scripting") {
            "Cross-Site Scripting".to_string()
        } else if desc.contains("rce")
            || desc.contains("remote code execution")
            || desc.contains("code execution")
        {
            "Remote Code Execution".to_string()
        } else if desc.contains("path traversal") || desc.contains("directory traversal") {
            "Path Traversal".to_string()
        } else if desc.contains("deserialization") {
            "Deserialization".to_string()
        } else if desc.contains("xxe") || desc.contains("xml external entity") {
            "XXE".to_string()
        } else if desc.contains("ssrf") || desc.contains("server-side request forgery") {
            "SSRF".to_string()
        } else if desc.contains("authentication") || desc.contains("auth bypass") {
            "Authentication Bypass".to_string()
        } else if desc.contains("privilege") || desc.contains("escalation") {
            "Privilege Escalation".to_string()
        } else if desc.contains("information disclosure") || desc.contains("information leak") {
            "Information Disclosure".to_string()
        } else {
            "Other".to_string()
        }
    }

    /// Generate threat intelligence summary
    pub fn generate_threat_intel(stack: &ProjectStack, cves: &[CveEntry]) -> String {
        let clusters = Self::cluster_by_pattern(cves);

        let mut intel = String::new();

        intel.push_str("=== Threat Intelligence Report ===\n\n");

        intel.push_str("Detected Stack:\n");
        intel.push_str(&format!("  Languages: {}\n", stack.languages.join(", ")));
        intel.push_str(&format!("  Frameworks: {}\n", stack.frameworks.join(", ")));
        intel.push_str(&format!("  Dependencies: {}\n\n", stack.dependencies.len()));

        intel.push_str("CVEs by Pattern:\n");
        for cluster in &clusters {
            intel.push_str(&format!(
                "  {}: {} CVEs\n",
                cluster.pattern_name, cluster.cve_count
            ));
            if !cluster.example_cves.is_empty() {
                intel.push_str(&format!(
                    "    Examples: {}\n",
                    cluster.example_cves.join(", ")
                ));
            }
        }

        let critical_count = cves
            .iter()
            .filter(|c| c.severity == V3Severity::Critical)
            .count();
        let high_count = cves
            .iter()
            .filter(|c| c.severity == V3Severity::High)
            .count();

        intel.push_str("\nSummary:\n");
        intel.push_str(&format!("  Critical: {}\n", critical_count));
        intel.push_str(&format!("  High: {}\n", high_count));
        intel.push_str(&format!("  Total CVEs: {}\n", cves.len()));

        intel
    }

    /// Enrich findings with CVE data
    pub async fn run_cve_enrichment(
        &self,
        findings: &[crate::findings::VulnerabilityFinding],
    ) -> Result<Vec<crate::findings::VulnerabilityFinding>> {
        use tracing::debug;

        // Detect project stack
        let stack = self.detect_project_stack()?;

        // Fetch relevant CVEs
        let cves = self.fetch_relevant_cves(&stack).await?;

        if cves.is_empty() {
            tracing::info!("No CVEs found for project stack");
            return Ok(findings.to_vec());
        }

        tracing::info!("Found {} CVEs for project dependencies", cves.len());

        // Build a map of CWE ID -> CVE entries for quick lookup
        let mut cve_by_cwe: std::collections::HashMap<String, Vec<&CveEntry>> =
            std::collections::HashMap::new();
        for cve in &cves {
            for cwe_id in &cve.cwe_ids {
                cve_by_cwe.entry(cwe_id.clone()).or_default().push(cve);
            }
        }

        // Enrich findings by matching CWE IDs
        let mut enriched_count = 0;
        let mut unmatched_count = 0;
        let mut enriched_findings = findings.to_vec();

        for finding in &mut enriched_findings {
            let cwe_matches = if let Some(ref cwe_id) = finding.cwe_id {
                cve_by_cwe.get(cwe_id).cloned()
            } else {
                None
            };

            if let Some(matching_cves) = cwe_matches {
                // Add CVE references as evidence
                for cve in matching_cves {
                    let cwe_id = finding.cwe_id.as_deref().unwrap_or("unknown");
                    finding.add_evidence(
                        crate::evidence::EvidenceSource::CweSpec(cwe_id.to_string()),
                        0.5,
                        format!("Related CVE: {} (severity: {:?})", cve.cve_id, cve.severity),
                    );
                }
                enriched_count += 1;
            } else {
                unmatched_count += 1;
            }
        }

        debug!(
            "CVE enrichment complete: {} findings enriched, {} unmatched",
            enriched_count, unmatched_count
        );

        Ok(enriched_findings)
    }
}
