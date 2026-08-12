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

fn build_harness_summary(harness: &AgentFlowHarness) -> String {
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

fn parse_rewrite_proposal(response: &str) -> Result<RewriteProposal, String> {
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

fn parse_single_edit(edit_json: &serde_json::Value) -> Option<HarnessEdit> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_flow::dsl::{Agent, AgentFlowHarness, EdgeKind};
    use std::collections::BTreeSet;

    fn agent(role: &str) -> Agent {
        Agent {
            role: role.to_string(),
            prompt: format!("{{{{ {}.out }}}}", role),
            model: "test".to_string(),
            tools: BTreeSet::new(),
        }
    }

    fn simple_harness() -> AgentFlowHarness {
        let mut h = AgentFlowHarness::new();
        let a = h.add_agent(agent("analyst"));
        let b = h.add_agent(agent("validator"));
        h.add_edge(a, b, EdgeKind::Data, "{{ analyst.out }}".to_string());
        h
    }

    #[test]
    fn test_apply_add_agent() {
        let proposal = RewriteProposal {
            edits: vec![HarnessEdit::AddAgent {
                role: "reviewer".into(),
                prompt: "review".into(),
            }],
            rationale: "add reviewer".into(),
        };
        let h = simple_harness();
        let new_h = apply_rewrite(&h, &proposal);
        assert_eq!(new_h.nodes.len(), 3);
    }

    #[test]
    fn test_apply_remove_agent() {
        let proposal = RewriteProposal {
            edits: vec![HarnessEdit::RemoveAgent {
                role: "validator".into(),
            }],
            rationale: "remove".into(),
        };
        let h = simple_harness();
        let new_h = apply_rewrite(&h, &proposal);
        assert_eq!(new_h.nodes.len(), 1);
        assert!(new_h.edges.is_empty());
    }

    #[test]
    fn test_apply_update_prompt() {
        let proposal = RewriteProposal {
            edits: vec![HarnessEdit::UpdatePrompt {
                role: "analyst".into(),
                new_prompt: "new prompt".into(),
            }],
            rationale: "update".into(),
        };
        let h = simple_harness();
        let new_h = apply_rewrite(&h, &proposal);
        for node in &new_h.nodes {
            if let crate::agent_flow::dsl::NodeKind::Agent(a) = &node.kind {
                if a.role == "analyst" {
                    assert_eq!(a.prompt, "new prompt");
                }
            }
        }
    }

    #[test]
    fn test_apply_add_edge() {
        let proposal = RewriteProposal {
            edits: vec![HarnessEdit::AddEdge {
                from_role: "validator".into(),
                to_role: "analyst".into(),
                kind: "data".into(),
                template: "{{ validator.out }}".into(),
            }],
            rationale: "add edge".into(),
        };
        let h = simple_harness();
        let new_h = apply_rewrite(&h, &proposal);
        assert_eq!(new_h.edges.len(), 2);
    }

    #[test]
    fn test_build_harness_summary() {
        let h = simple_harness();
        let summary = build_harness_summary(&h);
        assert!(summary.contains("analyst"));
        assert!(summary.contains("validator"));
        assert!(summary.contains("Edges:"));
    }

    #[test]
    fn test_build_harness_summary_empty() {
        let h = AgentFlowHarness::new();
        let summary = build_harness_summary(&h);
        assert!(summary.contains("Agents:"));
        assert!(summary.contains("Edges:"));
    }

    #[test]
    fn test_parse_rewrite_proposal_empty_response() {
        let response = "";
        let proposal = parse_rewrite_proposal(response).unwrap();
        assert!(proposal.edits.is_empty());
        assert!(!proposal.rationale.is_empty());
    }

    #[test]
    fn test_parse_single_edit_add_agent() {
        let edit_json = serde_json::json!({
            "type": "AddAgent",
            "role": "reviewer",
            "prompt": "Review the findings"
        });
        let edit = parse_single_edit(&edit_json).unwrap();
        match edit {
            HarnessEdit::AddAgent { role, prompt } => {
                assert_eq!(role, "reviewer");
                assert_eq!(prompt, "Review the findings");
            }
            _ => panic!("Expected AddAgent edit"),
        }
    }

    #[test]
    fn test_parse_single_edit_remove_agent() {
        let edit_json = serde_json::json!({
            "type": "RemoveAgent",
            "role": "validator"
        });
        let edit = parse_single_edit(&edit_json).unwrap();
        match edit {
            HarnessEdit::RemoveAgent { role } => {
                assert_eq!(role, "validator");
            }
            _ => panic!("Expected RemoveAgent edit"),
        }
    }

    #[test]
    fn test_parse_single_edit_update_prompt() {
        let edit_json = serde_json::json!({
            "type": "UpdatePrompt",
            "role": "analyst",
            "new_prompt": "Updated prompt"
        });
        let edit = parse_single_edit(&edit_json).unwrap();
        match edit {
            HarnessEdit::UpdatePrompt { role, new_prompt } => {
                assert_eq!(role, "analyst");
                assert_eq!(new_prompt, "Updated prompt");
            }
            _ => panic!("Expected UpdatePrompt edit"),
        }
    }

    #[test]
    fn test_parse_single_edit_unknown_type() {
        let edit_json = serde_json::json!({
            "type": "UnknownType",
            "role": "test"
        });
        let edit = parse_single_edit(&edit_json);
        assert!(edit.is_none());
    }

    #[test]
    fn test_parse_single_edit_missing_field() {
        let edit_json = serde_json::json!({
            "type": "AddAgent",
            "role": "reviewer"
        });
        let edit = parse_single_edit(&edit_json);
        assert!(edit.is_none());
    }
}
