//! Proposer for AgentFlow harness rewrites (P5.5).
//!
//! Takes a diagnostic and proposes a harness rewrite: adding/removing agents,
//! changing edges, or modifying prompt templates. Calls the LLM to generate
//! rewrite suggestions.

use super::diagnoser::{format_diagnostic, Diagnostic};
use super::dsl::{AgentFlowHarness, EdgeKind};
use crate::llm::LlmClient;

/// A single proposed edit to a harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarnessEdit {
    AddAgent {
        role: String,
        prompt: String,
    },
    RemoveAgent {
        role: String,
    },
    AddEdge {
        from_role: String,
        to_role: String,
        kind: String,
        template: String,
    },
    RemoveEdge {
        from_role: String,
        to_role: String,
    },
    UpdatePrompt {
        role: String,
        new_prompt: String,
    },
}

/// A complete rewrite proposal: a list of edits + rationale.
#[derive(Debug, Clone)]
pub struct RewriteProposal {
    pub edits: Vec<HarnessEdit>,
    pub rationale: String,
}

/// Propose a harness rewrite based on the diagnostic using LLM.
pub async fn propose_rewrite(
    llm: &LlmClient,
    diagnostic: &Diagnostic,
    harness: &AgentFlowHarness,
) -> Result<RewriteProposal, String> {
    let formatted_diagnostic = format_diagnostic(diagnostic);
    let harness_summary = build_harness_summary(harness);

    let messages = vec![
        crate::llm::ChatMessage::system(
            "You are an AgentFlow harness optimizer. Analyze the diagnostic feedback and propose specific edits to improve the harness. Output your response as a JSON object with 'edits' array and 'rationale' string.",
        ),
        crate::llm::ChatMessage::user(&format!(
            "Current harness summary:\n{}\n\nDiagnostic feedback:\n{}\n\nPropose edits to fix issues. Available edit types:\n- AddAgent: add a new agent with role and prompt\n- RemoveAgent: remove an agent by role\n- AddEdge: add an edge between agents\n- RemoveEdge: remove an edge between agents\n- UpdatePrompt: update an agent's prompt",
            harness_summary, formatted_diagnostic
        )),
    ];

    let response = llm
        .chat(&messages)
        .await
        .map_err(|e| format!("LLM call failed for propose_rewrite: {}", e))?;

    parse_rewrite_proposal(&response.content)
}

pub fn build_harness_summary(harness: &AgentFlowHarness) -> String {
    let mut agents = Vec::new();
    for node in &harness.nodes {
        if let super::dsl::NodeKind::Agent(a) = &node.kind {
            agents.push(format!(
                "- {} (prompt length: {} chars)",
                a.role,
                a.prompt.len()
            ));
        }
    }

    let mut edges = Vec::new();
    for edge in &harness.edges {
        let kind_str = match edge.kind {
            super::dsl::EdgeKind::Data => "data",
            super::dsl::EdgeKind::Guarded(_) => "guarded",
        };
        let from_role = harness
            .nodes
            .get(edge.from)
            .and_then(|n| {
                if let super::dsl::NodeKind::Agent(a) = &n.kind {
                    Some(a.role.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_string());
        let to_role = harness
            .nodes
            .get(edge.to)
            .and_then(|n| {
                if let super::dsl::NodeKind::Agent(a) = &n.kind {
                    Some(a.role.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_string());
        edges.push(format!("{} -> {} ({})", from_role, to_role, kind_str));
    }

    format!(
        "Agents:\n{}\n\nEdges:\n{}",
        agents.join("\n"),
        edges.join("\n")
    )
}

pub fn parse_rewrite_proposal(response: &str) -> Result<RewriteProposal, String> {
    let trimmed = response.trim();

    if trimmed.starts_with('{') {
        if let Ok(json) = serde_json::from_str::<ParsedProposal>(trimmed) {
            let edits = json
                .edits
                .into_iter()
                .filter_map(|edit_json| parse_single_edit(&edit_json))
                .collect();
            return Ok(RewriteProposal {
                edits,
                rationale: json.rationale,
            });
        }
    }

    let rationale = "LLM-generated rewrite proposal".to_string();
    Ok(RewriteProposal {
        edits: Vec::new(),
        rationale,
    })
}

#[derive(Debug, serde::Deserialize)]
struct ParsedProposal {
    rationale: String,
    edits: Vec<serde_json::Value>,
}

pub fn parse_single_edit(edit_json: &serde_json::Value) -> Option<HarnessEdit> {
    let edit_type = edit_json.get("type")?.as_str()?;

    match edit_type {
        "AddAgent" => {
            let role = edit_json.get("role")?.as_str()?.to_string();
            let prompt = edit_json.get("prompt")?.as_str()?.to_string();
            Some(HarnessEdit::AddAgent { role, prompt })
        }
        "RemoveAgent" => {
            let role = edit_json.get("role")?.as_str()?.to_string();
            Some(HarnessEdit::RemoveAgent { role })
        }
        "UpdatePrompt" => {
            let role = edit_json.get("role")?.as_str()?.to_string();
            let new_prompt = edit_json.get("new_prompt")?.as_str()?.to_string();
            Some(HarnessEdit::UpdatePrompt { role, new_prompt })
        }
        _ => None,
    }
}

/// Apply a rewrite proposal to a harness, returning a new harness.
pub fn apply_rewrite(harness: &AgentFlowHarness, proposal: &RewriteProposal) -> AgentFlowHarness {
    let mut new_harness = harness.clone();

    for edit in &proposal.edits {
        match edit {
            HarnessEdit::AddAgent { role, prompt } => {
                new_harness.add_agent(super::dsl::Agent {
                    role: role.clone(),
                    prompt: prompt.clone(),
                    model: "default".to_string(),
                    tools: std::collections::BTreeSet::new(),
                });
            }
            HarnessEdit::RemoveAgent { role } => {
                if let Some(idx) = new_harness.nodes.iter().position(
                    |n| matches!(&n.kind, super::dsl::NodeKind::Agent(a) if a.role == *role),
                ) {
                    new_harness.nodes.remove(idx);
                    new_harness.edges.retain(|e| e.from != idx && e.to != idx);
                    for node in &mut new_harness.nodes {
                        if node.idx > idx {
                            node.idx -= 1;
                        }
                    }
                    for edge in &mut new_harness.edges {
                        if edge.from > idx {
                            edge.from -= 1;
                        }
                        if edge.to > idx {
                            edge.to -= 1;
                        }
                    }
                }
            }
            HarnessEdit::AddEdge {
                from_role,
                to_role,
                kind,
                template,
            } => {
                let from_idx = new_harness.nodes.iter().find_map(|n| match &n.kind {
                    super::dsl::NodeKind::Agent(a) if a.role == *from_role => Some(n.idx),
                    _ => None,
                });
                let to_idx = new_harness.nodes.iter().find_map(|n| match &n.kind {
                    super::dsl::NodeKind::Agent(a) if a.role == *to_role => Some(n.idx),
                    _ => None,
                });
                if let (Some(from), Some(to)) = (from_idx, to_idx) {
                    let edge_kind = if kind == "guarded" {
                        EdgeKind::Guarded("fail".to_string())
                    } else {
                        EdgeKind::Data
                    };
                    new_harness.add_edge(from, to, edge_kind, template.clone());
                }
            }
            HarnessEdit::RemoveEdge { from_role, to_role } => {
                let from_idx = new_harness.nodes.iter().find_map(|n| match &n.kind {
                    super::dsl::NodeKind::Agent(a) if a.role == *from_role => Some(n.idx),
                    _ => None,
                });
                let to_idx = new_harness.nodes.iter().find_map(|n| match &n.kind {
                    super::dsl::NodeKind::Agent(a) if a.role == *to_role => Some(n.idx),
                    _ => None,
                });
                if let (Some(from), Some(to)) = (from_idx, to_idx) {
                    new_harness
                        .edges
                        .retain(|e| !(e.from == from && e.to == to));
                }
            }
            HarnessEdit::UpdatePrompt { role, new_prompt } => {
                for node in &mut new_harness.nodes {
                    if let super::dsl::NodeKind::Agent(a) = &mut node.kind {
                        if a.role == *role {
                            a.prompt = new_prompt.clone();
                        }
                    }
                }
            }
        }
    }

    new_harness
}
