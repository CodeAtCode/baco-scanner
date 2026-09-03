//! Well-formedness checker for AgentFlow harnesses (P5.2).
//!
//! Validates structural invariants before runtime execution:
//! - Edge endpoints reference existing nodes
//! - No cycles through `Data` edges (Guarded edges may form loops)
//! - Fanout node references are valid
//! - Template variables reference existing upstream agent roles

use super::dsl::{AgentFlowHarness, EdgeKind, NodeKind};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeError {
    UnknownNode { edge_idx: usize, endpoint: usize },
    FanoutTargetMissing { node_idx: usize, target: usize },
    CycleInDataEdges { nodes: Vec<usize> },
    TemplateVarMissing { edge_idx: usize, var: String },
    EmptyHarness,
    DuplicateRole { role: String },
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownNode { edge_idx, endpoint } => {
                write!(f, "edge {} references unknown node {}", edge_idx, endpoint)
            }
            Self::FanoutTargetMissing { node_idx, target } => {
                write!(
                    f,
                    "fanout node {} targets missing node {}",
                    node_idx, target
                )
            }
            Self::CycleInDataEdges { nodes } => {
                write!(f, "cycle in data edges: {:?}", nodes)
            }
            Self::TemplateVarMissing { edge_idx, var } => {
                write!(
                    f,
                    "edge {} template references unknown agent: {}",
                    edge_idx, var
                )
            }
            Self::EmptyHarness => write!(f, "harness has no nodes"),
            Self::DuplicateRole { role } => write!(f, "duplicate agent role: {}", role),
        }
    }
}

impl std::error::Error for TypeError {}

pub type TypeResult<T> = Result<T, TypeError>;

/// Check that a harness is well-formed. Returns `Ok(())` if valid,
/// or the first `TypeError` encountered.
pub fn typecheck(harness: &AgentFlowHarness) -> TypeResult<()> {
    if harness.nodes.is_empty() {
        return Err(TypeError::EmptyHarness);
    }

    let node_indices: BTreeSet<usize> = harness.nodes.iter().map(|n| n.idx).collect();

    check_edges(harness, &node_indices)?;
    check_fanouts(harness, &node_indices)?;
    check_no_data_cycles(harness)?;
    check_duplicate_roles(harness)?;
    check_templates(harness)?;

    Ok(())
}

fn check_edges(harness: &AgentFlowHarness, node_indices: &BTreeSet<usize>) -> TypeResult<()> {
    for (i, edge) in harness.edges.iter().enumerate() {
        if !node_indices.contains(&edge.from) {
            return Err(TypeError::UnknownNode {
                edge_idx: i,
                endpoint: edge.from,
            });
        }
        if !node_indices.contains(&edge.to) {
            return Err(TypeError::UnknownNode {
                edge_idx: i,
                endpoint: edge.to,
            });
        }
    }
    Ok(())
}

fn check_fanouts(harness: &AgentFlowHarness, node_indices: &BTreeSet<usize>) -> TypeResult<()> {
    for node in &harness.nodes {
        if let NodeKind::Fanout { node_idx, .. } = &node.kind {
            if !node_indices.contains(node_idx) {
                return Err(TypeError::FanoutTargetMissing {
                    node_idx: node.idx,
                    target: *node_idx,
                });
            }
        }
    }
    Ok(())
}

fn check_no_data_cycles(harness: &AgentFlowHarness) -> TypeResult<()> {
    let data_edges: Vec<(usize, usize)> = harness
        .edges
        .iter()
        .filter(|e| matches!(e.kind, EdgeKind::Data))
        .map(|e| (e.from, e.to))
        .collect();

    if let Some(cycle) = find_cycle(&data_edges) {
        return Err(TypeError::CycleInDataEdges { nodes: cycle });
    }
    Ok(())
}

fn find_cycle(edges: &[(usize, usize)]) -> Option<Vec<usize>> {
    let mut adj: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &(from, to) in edges {
        adj.entry(from).or_default().push(to);
    }

    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut on_stack: BTreeSet<usize> = BTreeSet::new();

    for &start in adj.keys() {
        if visited.contains(&start) {
            continue;
        }
        if let Some(cycle) = dfs_cycle(start, &adj, &mut visited, &mut stack, &mut on_stack) {
            return Some(cycle);
        }
    }
    None
}

fn dfs_cycle(
    node: usize,
    adj: &BTreeMap<usize, Vec<usize>>,
    visited: &mut BTreeSet<usize>,
    stack: &mut Vec<usize>,
    on_stack: &mut BTreeSet<usize>,
) -> Option<Vec<usize>> {
    visited.insert(node);
    on_stack.insert(node);
    stack.push(node);

    if let Some(neighbors) = adj.get(&node) {
        for &next in neighbors {
            if on_stack.contains(&next) {
                let cycle_start = stack.iter().position(|&n| n == next).unwrap();
                return Some(stack[cycle_start..].to_vec());
            }
            if !visited.contains(&next) {
                if let Some(cycle) = dfs_cycle(next, adj, visited, stack, on_stack) {
                    return Some(cycle);
                }
            }
        }
    }

    on_stack.remove(&node);
    stack.pop();
    None
}

fn check_duplicate_roles(harness: &AgentFlowHarness) -> TypeResult<()> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for node in &harness.nodes {
        if let NodeKind::Agent(agent) = &node.kind {
            if !seen.insert(agent.role.clone()) {
                return Err(TypeError::DuplicateRole {
                    role: agent.role.clone(),
                });
            }
        }
    }
    Ok(())
}

fn check_templates(harness: &AgentFlowHarness) -> TypeResult<()> {
    let roles: BTreeSet<String> = harness
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            NodeKind::Agent(a) => Some(a.role.clone()),
            NodeKind::Fanout { .. } => None,
        })
        .collect();

    for (i, edge) in harness.edges.iter().enumerate() {
        for var in extract_template_vars(&edge.template) {
            if !roles.contains(&var) {
                return Err(TypeError::TemplateVarMissing { edge_idx: i, var });
            }
        }
    }
    Ok(())
}

/// Extract `{{ var.out }}` style variables from a template string.
fn extract_template_vars(template: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        rest = &rest[start + 2..];
        if let Some(end) = rest.find("}}") {
            let token = rest[..end].trim();
            if let Some(role) = token.split('.').next() {
                let role = role.trim();
                if !role.is_empty() {
                    vars.push(role.to_string());
                }
            }
            rest = &rest[end + 2..];
        } else {
            break;
        }
    }
    vars
}
