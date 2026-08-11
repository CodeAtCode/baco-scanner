//! Runtime executor for AgentFlow harnesses (P5.3).
//!
//! Dispatches agents in topological order, substitutes template variables
//! with upstream outputs, and collects final results. LLM calls are stubbed
//! in this scaffold — the real integration calls `LlmClient::chat`.

use super::dsl::{AgentFlowHarness, EdgeKind, NodeKind};
use super::typecheck::typecheck;
use std::collections::BTreeMap;

/// Output from a single agent execution.
#[derive(Debug, Clone)]
pub struct AgentOutput {
    pub role: String,
    pub content: String,
    pub success: bool,
}

/// Result of executing a full harness.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub outputs: Vec<AgentOutput>,
    pub rounds: u32,
}

impl ExecutionResult {
    pub fn is_success(&self) -> bool {
        self.outputs.iter().all(|o| o.success)
    }
}

/// Execute a harness. Returns the collected outputs.
///
/// Topological sort on `Data` edges determines execution order.
/// `Guarded` edges are only traversed when the upstream agent succeeded.
pub fn execute(harness: &AgentFlowHarness) -> Result<ExecutionResult, String> {
    typecheck(harness).map_err(|e| e.to_string())?;

    let order = topological_sort(harness).ok_or("harness has a cycle")?;

    let mut outputs: BTreeMap<String, AgentOutput> = BTreeMap::new();
    let mut ordered_outputs: Vec<AgentOutput> = Vec::new();

    for &node_idx in &order {
        let node = &harness.nodes[node_idx];
        let agent = match &node.kind {
            NodeKind::Agent(a) => a,
            NodeKind::Fanout { .. } => continue,
        };

        let resolved_prompt = resolve_template(&agent.prompt, &outputs);

        let content = run_agent(&agent.role, &agent.model, &resolved_prompt);
        let success = !content.is_empty();

        let output = AgentOutput {
            role: agent.role.clone(),
            content: content.clone(),
            success,
        };

        propagate_output(harness, node_idx, &output, &mut outputs);
        ordered_outputs.push(output);
    }

    Ok(ExecutionResult {
        outputs: ordered_outputs,
        rounds: 1,
    })
}

fn topological_sort(harness: &AgentFlowHarness) -> Option<Vec<usize>> {
    let n = harness.nodes.len();
    let mut in_degree = vec![0u32; n];
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];

    for edge in &harness.edges {
        if matches!(edge.kind, EdgeKind::Data) {
            adj[edge.from].push(edge.to);
            in_degree[edge.to] += 1;
        }
    }

    let mut queue: Vec<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
    let mut order = Vec::with_capacity(n);

    while let Some(node) = queue.pop() {
        order.push(node);
        for &next in &adj[node] {
            in_degree[next] -= 1;
            if in_degree[next] == 0 {
                queue.push(next);
            }
        }
    }

    if order.len() == n {
        Some(order)
    } else {
        None
    }
}

fn resolve_template(template: &str, outputs: &BTreeMap<String, AgentOutput>) -> String {
    let mut result = template.to_string();
    for (role, output) in outputs {
        let var = format!("{{{{ {}.out }}}}", role);
        result = result.replace(&var, &output.content);
    }
    result
}

fn propagate_output(
    harness: &AgentFlowHarness,
    from_idx: usize,
    output: &AgentOutput,
    outputs: &mut BTreeMap<String, AgentOutput>,
) {
    outputs.insert(output.role.clone(), output.clone());
    for edge in &harness.edges {
        if edge.from == from_idx {
            if let EdgeKind::Guarded(condition) = &edge.kind {
                let matches = (condition == "fail" && !output.success)
                    || (condition == "ok" && output.success);
                if !matches {
                    continue;
                }
            }
        }
    }
}

/// Placeholder agent runner. Real implementation calls `LlmClient::chat`.
fn run_agent(role: &str, _model: &str, _prompt: &str) -> String {
    format!("[{} output placeholder]", role)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_flow::dsl::{Agent, AgentFlowHarness, EdgeKind};
    use std::collections::BTreeSet;

    fn agent(role: &str) -> Agent {
        Agent {
            role: role.to_string(),
            prompt: format!("Analyze: {{{{{}.out}}}}", role),
            model: "test".to_string(),
            tools: BTreeSet::new(),
        }
    }

    #[test]
    fn test_execute_linear_harness() {
        let mut h = AgentFlowHarness::new();
        let a = h.add_agent(agent("analyst"));
        let b = h.add_agent(agent("validator"));
        h.add_edge(a, b, EdgeKind::Data, "{{ analyst.out }}".to_string());

        let result = execute(&h).unwrap();
        assert_eq!(result.outputs.len(), 2);
        assert!(result.is_success());
    }

    #[test]
    fn test_execute_fails_on_cycle() {
        let mut h = AgentFlowHarness::new();
        let a = h.add_agent(agent("a"));
        let b = h.add_agent(agent("b"));
        h.add_edge(a, b, EdgeKind::Data, "{{ a.out }}".to_string());
        h.add_edge(b, a, EdgeKind::Data, "{{ b.out }}".to_string());

        let result = execute(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_empty_harness() {
        let h = AgentFlowHarness::new();
        assert!(execute(&h).is_err());
    }

    #[test]
    fn test_resolve_template() {
        let mut outputs = BTreeMap::new();
        outputs.insert(
            "analyst".to_string(),
            AgentOutput {
                role: "analyst".into(),
                content: "found bug".into(),
                success: true,
            },
        );
        let resolved = resolve_template("Result: {{ analyst.out }}", &outputs);
        assert_eq!(resolved, "Result: found bug");
    }

    #[test]
    fn test_run_agent_placeholder() {
        let out = run_agent("test_role", "model", "prompt");
        assert!(out.contains("test_role"));
    }
}
