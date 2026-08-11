//! Typed-graph DSL for multi-agent harnesses (P5.1).
//!
//! A harness H = (A, G, Σ, Φ, Ψ):
//! - A: agent set, each (role, prompt, model, tools)
//! - G ⊆ A × A: directed communication topology
//! - Σ: per-edge message schema (Jinja templates referencing upstream outputs)
//! - Φ: A → 2^Tools: tool allocation per agent
//! - Ψ: coordination protocol (sequential, parallel, fan-out, retry-until-success)
//!
//! Well-formedness checks (type system) are implemented in `typecheck.rs` (P5.2).

use std::collections::BTreeSet;

/// An agent in the harness: role, prompt template, model, and allocated tools.
#[derive(Debug, Clone)]
pub struct Agent {
    pub role: String,
    pub prompt: String,
    pub model: String,
    pub tools: BTreeSet<String>,
}

/// Feedback channels that agents can reference in prompt templates.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FeedbackChannel {
    Coverage,
    Branch,
    Sanitizer,
    Trace(String),
    Outcome,
}

/// A node in the harness graph: either a single agent or a fan-out of k copies.
#[derive(Debug, Clone)]
pub enum NodeKind {
    Agent(Agent),
    Fanout { node_idx: usize, k: usize },
}

/// A graph node with an index for edge referencing.
#[derive(Debug, Clone)]
pub struct Node {
    pub idx: usize,
    pub kind: NodeKind,
}

/// Edge kind: plain data flow or guarded (ok/fail) control flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeKind {
    Data,
    Guarded(String),
}

/// A directed edge in the communication topology.
#[derive(Debug, Clone)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
    pub kind: EdgeKind,
    /// Jinja-style message template, e.g. `"{{ analyst.out }}"`.
    pub template: String,
}

/// The full harness: nodes, edges, and feedback channels.
#[derive(Debug, Clone, Default)]
pub struct AgentFlowHarness {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub feedback: BTreeSet<FeedbackChannel>,
}

impl AgentFlowHarness {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_agent(&mut self, agent: Agent) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(Node {
            idx,
            kind: NodeKind::Agent(agent),
        });
        idx
    }

    pub fn add_edge(&mut self, from: usize, to: usize, kind: EdgeKind, template: String) {
        self.edges.push(Edge {
            from,
            to,
            kind,
            template,
        });
    }

    pub fn add_fanout(&mut self, node_idx: usize, k: usize) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(Node {
            idx,
            kind: NodeKind::Fanout { node_idx, k },
        });
        idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_agent(role: &str) -> Agent {
        Agent {
            role: role.to_string(),
            prompt: format!("Analyze: {{{{{role}.out}}}}"),
            model: "test-model".to_string(),
            tools: BTreeSet::new(),
        }
    }

    #[test]
    fn test_build_simple_harness() {
        let mut h = AgentFlowHarness::new();
        let analyst = h.add_agent(sample_agent("analyst"));
        let validator = h.add_agent(sample_agent("validator"));
        h.add_edge(
            analyst,
            validator,
            EdgeKind::Data,
            "{{ analyst.out }}".to_string(),
        );
        assert_eq!(h.nodes.len(), 2);
        assert_eq!(h.edges.len(), 1);
    }

    #[test]
    fn test_fanout_node() {
        let mut h = AgentFlowHarness::new();
        let analyst = h.add_agent(sample_agent("analyst"));
        let fanout = h.add_fanout(analyst, 8);
        assert_eq!(fanout, 1);
        match &h.nodes[1].kind {
            NodeKind::Fanout { node_idx, k } => {
                assert_eq!(*node_idx, 0);
                assert_eq!(*k, 8);
            }
            _ => panic!("expected Fanout"),
        }
    }

    #[test]
    fn test_guarded_edge() {
        let mut h = AgentFlowHarness::new();
        let a = h.add_agent(sample_agent("a"));
        let b = h.add_agent(sample_agent("b"));
        h.add_edge(
            a,
            b,
            EdgeKind::Guarded("fail".to_string()),
            "{{ a.out }}".to_string(),
        );
        match &h.edges[0].kind {
            EdgeKind::Guarded(g) => assert_eq!(g, "fail"),
            _ => panic!("expected Guarded edge"),
        }
    }
}
