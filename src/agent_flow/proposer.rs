//! Proposer for AgentFlow harness rewrites (P5.5).
//!
//! Takes a diagnostic and proposes a harness rewrite: adding/removing agents,
//! changing edges, or modifying prompt templates. The real implementation
//! calls the LLM; this scaffold provides the rewrite-suggestion data model
//! and a deterministic fallback proposer.

use super::diagnoser::Diagnostic;
use super::dsl::{AgentFlowHarness, EdgeKind};

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

/// Propose a harness rewrite based on the diagnostic.
///
/// Deterministic fallback: if no LLM is available, applies simple rules
/// (e.g., add a reviewer agent if one is missing).
pub fn propose_rewrite(diagnostic: &Diagnostic, harness: &AgentFlowHarness) -> RewriteProposal {
    let mut edits = Vec::new();
    let mut rationale_parts = Vec::new();

    if diagnostic.should_rewrite {
        let has_reviewer = harness.nodes.iter().any(|n| {
            if let super::dsl::NodeKind::Agent(a) = &n.kind {
                a.role == "reviewer"
            } else {
                false
            }
        });

        if !has_reviewer {
            edits.push(HarnessEdit::AddAgent {
                role: "reviewer".to_string(),
                prompt:
                    "Review the analysis for false positives. {{ analyst.out }} {{ validator.out }}"
                        .to_string(),
            });
            rationale_parts.push("added reviewer agent for quality gate".to_string());
        }

        if diagnostic.summary.contains("failed agents") {
            rationale_parts.push("some agents failed — retry with simplified prompts".to_string());
            for node in &harness.nodes {
                if let super::dsl::NodeKind::Agent(a) = &node.kind {
                    if a.prompt.len() > 500 {
                        edits.push(HarnessEdit::UpdatePrompt {
                            role: a.role.clone(),
                            new_prompt: "Analyze the target concisely.".to_string(),
                        });
                    }
                }
            }
        }
    }

    RewriteProposal {
        edits,
        rationale: rationale_parts.join("; "),
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
    use crate::agent_flow::diagnoser::{Diagnostic, FeedbackSignal};
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
    fn test_propose_adds_reviewer_when_missing() {
        let diag = Diagnostic {
            signals: vec![FeedbackSignal::Fail("no".into())],
            summary: "failed agents: validator".into(),
            should_rewrite: true,
        };
        let h = simple_harness();
        let proposal = propose_rewrite(&diag, &h);
        assert!(proposal
            .edits
            .iter()
            .any(|e| matches!(e, HarnessEdit::AddAgent { role, .. } if role == "reviewer")));
    }

    #[test]
    fn test_propose_no_rewrite_when_success() {
        let diag = Diagnostic {
            signals: vec![FeedbackSignal::Pass],
            summary: "ok".into(),
            should_rewrite: false,
        };
        let h = simple_harness();
        let proposal = propose_rewrite(&diag, &h);
        assert!(proposal.edits.is_empty());
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
}
