//! Org-context profile rendering for prompt calibration.
//! Populated by the org-context lane: renders meaning-attached guidance
//! from the `[org_context]` config section.

use crate::config::OrgContextConfig;

/// Render the org-context prompt block.
///
/// Returns `None` when disabled OR all optional fields empty.
/// Otherwise returns a "=== ORG CONTEXT ===" block with meaning-attached text
/// following the argus soul.go pattern — labels become instructions, not tokens.
pub fn render(cfg: &OrgContextConfig) -> Option<String> {
    if !cfg.enabled {
        return None;
    }

    // Check if any optional field has content
    let has_content = !cfg.stack.is_empty()
        || !cfg.infra.is_empty()
        || cfg.data_sensitivity.is_some()
        || cfg.secret_storage.is_some()
        || cfg.risk_tolerance.is_some()
        || !cfg.severity_rules.is_empty();

    if !has_content {
        return None;
    }

    let mut lines = Vec::new();
    lines.push("=== ORG CONTEXT ===".to_string());
    lines.push(
        "Organizational policy profile for prompt calibration. Treat each line as an instruction."
            .to_string(),
    );
    lines.push(String::new());

    // Stack and infra → target identification with idiomatic checks
    if !cfg.stack.is_empty() || !cfg.infra.is_empty() {
        let target_parts: Vec<String> = cfg.stack.iter().chain(cfg.infra.iter()).cloned().collect();
        lines.push(format!(
            "The target is {}; apply checks idiomatic to this stack.",
            target_parts.join(", ")
        ));
        lines.push(String::new());
    }

    // Data sensitivity
    if let Some(ref sensitivity) = cfg.data_sensitivity {
        match sensitivity.to_lowercase().as_str() {
            "pii" => {
                lines.push(
                    "Treat any exposure of personal data as at least High severity regardless of other scoring."
                        .to_string(),
                );
            }
            other => {
                lines.push(format!(
                    "Data sensitivity level: {}. Apply appropriate handling guidance.",
                    other
                ));
            }
        }
        lines.push(String::new());
    }

    // Secret storage
    if let Some(ref storage) = cfg.secret_storage {
        match storage.to_lowercase().as_str() {
            "vault" => {
                lines.push(
                    "Production secrets come from Vault: ${VAULT_TOKEN}-style references are placeholders, NOT leaked secrets — do not report them as findings."
                        .to_string(),
                );
            }
            other => {
                lines.push(format!(
                    "Secret storage: {}. Apply appropriate secret-handling guidance.",
                    other
                ));
            }
        }
        lines.push(String::new());
    }

    // Risk tolerance — MUST include anti-misread note
    if let Some(ref tolerance) = cfg.risk_tolerance {
        lines.push(format!("Risk tolerance: '{}'.", tolerance));
        lines.push(
            "'{}' does NOT mean only report criticals — it means prioritize ruthlessly; report everything real, ordered."
                .replace("{}", tolerance),
        );
        lines.push(String::new());
    }

    // Severity rules → OVERRIDE lines
    for (key, value) in &cfg.severity_rules {
        lines.push(format!("OVERRIDE: {} → {}", key, value));
    }

    Some(lines.join("\n"))
}
