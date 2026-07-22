use super::{PhaseContext, PhaseError, ScanPhase};
use crate::findings::VulnerabilityFinding;
use crate::indexer::FileIndex;
use crate::llm::LlmClient;
use crate::llm::LlmConfig;
use crate::llm_analysis::LlmAnalyzer;
use async_trait::async_trait;

pub struct LlmStaticAnalysisPhase;

#[async_trait]
impl ScanPhase for LlmStaticAnalysisPhase {
    fn name(&self) -> &'static str {
        "LlmStaticAnalysis"
    }

    fn order(&self) -> u8 {
        3
    }

    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        tracing::info!(
            "Running LLM static analysis on {:?}",
            ctx.scanner.target_path
        );
        tracing::info!("[LLM] Phase started");
        tracing::info!("[LLM] Checking for api_key in config...");

        // Quick connectivity check: test LLM endpoint before processing files
        let phase_config = &ctx.scanner.config.llm.phases.discovery;
        tracing::info!(
            "[LLM] Phase config: base_url={}, api_key={:?}",
            phase_config.base_url,
            phase_config.api_key
        );

        if phase_config.api_key.is_none() {
            tracing::warn!("[LLM] No API key found - skipping connectivity check");
        }

        if let Some(api_key) = &phase_config.api_key {
            tracing::info!("[LLM] API key found, starting connectivity check...");
            let llm_config = LlmConfig {
                base_url: ctx.scanner.config.llm.phases.discovery.base_url.clone(),
                api_key: api_key.clone(),
                model: ctx.scanner.config.llm.phases.discovery.model.clone(),
                models: ctx.scanner.config.llm.phases.discovery.get_models(),
                timeout: 5, // Very short timeout for connectivity check
                max_retries: 1,
                retry_backoff_ms: 0,
            };

            let test_client = LlmClient::new(llm_config);
            let test_messages = vec![crate::llm::ChatMessage {
                role: "user".to_string(),
                content: "ping".to_string(),
            }];

            tracing::debug!("[LLM] Testing endpoint connectivity...");
            let chat_result = test_client.chat(&test_messages).await;
            match chat_result {
                Ok(_) => {
                    tracing::debug!("[LLM] Endpoint is reachable");
                }
                Err(_e) => {
                    tracing::warn!(
                        "\u{1B}[33m[WARN]\u{1B}[0m LLM endpoint unreachable at {}: connection failed",
                        ctx.scanner.config.llm.phases.discovery.base_url
                    );
                    tracing::warn!(
                        "LLM static analysis skipped - endpoint unreachable. Continuing without LLM analysis."
                    );
                    tracing::warn!(
                        "To enable LLM analysis: fix the endpoint or check network connectivity."
                    );
                    return Ok(vec![]);
                }
            }
        }

        let index = match FileIndex::index_project(
            ctx.scanner.target_path.to_str().unwrap_or("."),
            &ctx.scanner.config.project.languages,
            ctx.scanner.config.scanner.max_file_size_kb * 1024,
            &ctx.scanner.config.scanner.exclude_paths,
        ) {
            Ok(idx) => {
                tracing::info!("[LLM] Indexing complete: {} files", idx.get_files().len());
                idx
            }
            Err(e) => {
                tracing::error!("[LLM] Indexing failed: {}", e);
                tracing::warn!("Failed to index project: {}", e);
                return Err(PhaseError {
                    phase_name: "LlmStaticAnalysis",
                    message: format!("Failed to index project: {}", e),
                });
            }
        };

        let files = index.get_files();
        let file_count = files.len();
        tracing::info!("[LLM] Found {} files to analyze", file_count);

        if let Some(api_key) = &ctx.scanner.config.llm.phases.discovery.api_key {
            let discovery_timeout = ctx
                .scanner
                .config
                .llm
                .phases
                .discovery
                .timeout_secs
                .unwrap_or(ctx.scanner.config.llm.timeout_secs);

            let llm_config = LlmConfig {
                base_url: ctx.scanner.config.llm.phases.discovery.base_url.clone(),
                api_key: api_key.clone(),
                model: ctx.scanner.config.llm.phases.discovery.model.clone(),
                models: ctx.scanner.config.llm.phases.discovery.get_models(),
                timeout: discovery_timeout,
                max_retries: ctx.scanner.config.llm.max_retries as u32,
                retry_backoff_ms: ctx.scanner.config.llm.retry_backoff_ms,
            };

            let client =
                LlmClient::with_metrics(llm_config, Some(ctx.scanner.metrics_tracker.clone()));
            let analyzer = LlmAnalyzer::new(
                client,
                ctx.scanner.config.project.languages.clone(),
                ctx.scanner.config.scanner.max_file_size_kb as usize,
                &ctx.scanner.config,
            );

            let mut llm_findings = Vec::new();

            for (i, file_info) in files.iter().enumerate() {
                let file_path_str = file_info.path.to_string_lossy().to_string();
                if ctx.analyzed_files.contains(&file_path_str) {
                    tracing::debug!("Skipping already analyzed: {}", file_path_str);
                    continue;
                }

                if i % 10 == 0 || i == files.len() - 1 {
                    tracing::info!(
                        "LLM analyzing [{}/{}]: {}",
                        i + 1,
                        file_count,
                        file_info.path.display()
                    );
                }

                match analyzer.analyze_file(&file_info.path).await {
                    Ok(findings) => {
                        if !findings.is_empty() {
                            let finding_infos: Vec<String> = findings
                                .iter()
                                .map(|f| {
                                    let cwe = f.cwe_id.as_deref().unwrap_or("Unknown");
                                    format!("{} ({:?} severity)", cwe, f.severity)
                                })
                                .collect();
                            let msg = format!(
                                "\u{1B}[32m[FOUND {}]\u{1B}[0m {} in {}: {}",
                                findings.len(),
                                if findings.len() == 1 {
                                    "vulnerability"
                                } else {
                                    "vulnerabilities"
                                },
                                file_info.path.display(),
                                finding_infos.join(", ")
                            );
                            tracing::info!("{}", msg);
                        }
                        llm_findings.extend(findings);
                        ctx.analyzed_files.push(file_path_str);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "\u{1B}[33m[WARN]\u{1B}[0m LLM analysis failed for {}: {}",
                            file_info.path.display(),
                            e
                        );
                        tracing::warn!(
                            "LLM analysis failed for {}: {}",
                            file_info.path.display(),
                            e
                        );
                    }
                }

                tokio::task::yield_now().await;
            }

            tracing::info!(
                "LLM static analysis complete - {} findings discovered",
                llm_findings.len()
            );
            Ok(llm_findings)
        } else {
            tracing::debug!("No API key for LLM analysis, skipping static analysis");
            Ok(Vec::new())
        }
    }

    fn is_enabled(&self, _ctx: &PhaseContext) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llm_static_phase_name() {
        let phase = LlmStaticAnalysisPhase;
        assert_eq!(phase.name(), "LlmStaticAnalysis");
    }

    #[test]
    fn test_llm_static_phase_order() {
        let phase = LlmStaticAnalysisPhase;
        assert_eq!(phase.order(), 3);
    }

    #[test]
    fn test_llm_static_phase_creation() {
        let _phase = LlmStaticAnalysisPhase;
        assert!(true);
    }
}
