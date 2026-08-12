//! Runtime executor for AgentFlow harnesses (P5.3).
//!
//! Dispatches agents in topological order, substitutes template variables
//! with upstream outputs, and collects final results. LLM calls are made
//! via `LlmClient::chat`.

use super::dsl::{AgentFlowHarness, EdgeKind, NodeKind};
use super::typecheck::typecheck;
use crate::llm::LlmClient;
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
pub async fn execute(
    harness: &AgentFlowHarness,
    llm: &LlmClient,
) -> Result<ExecutionResult, String> {
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

        let content = run_agent(llm, &agent.role, &resolved_prompt).await;
        let success = content.is_ok();

        let output = AgentOutput {
            role: agent.role.clone(),
            content: content.unwrap_or_default(),
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

/// Agent runner that calls the LLM.
async fn run_agent(llm: &LlmClient, role: &str, prompt: &str) -> Result<String, String> {
    let messages = vec![
        crate::llm::ChatMessage::system(&format!(
            "You are a vulnerability analysis agent with the role: {}. Your task is to analyze the provided code or findings and return a concise, actionable report.",
            role
        )),
        crate::llm::ChatMessage::user(prompt),
    ];

    let response = llm
        .chat(&messages)
        .await
        .map_err(|e| format!("LLM call failed for agent '{}': {}", role, e))?;

    Ok(response.content)
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
    fn test_topological_sort_linear() {
        let mut h = AgentFlowHarness::new();
        let a = h.add_agent(agent("analyst"));
        let b = h.add_agent(agent("validator"));
        h.add_edge(a, b, EdgeKind::Data, "{{ analyst.out }}".to_string());

        let order = topological_sort(&h);
        assert!(order.is_some());
        let order = order.unwrap();
        assert_eq!(order.len(), 2);
        assert_eq!(order[0], a);
        assert_eq!(order[1], b);
    }

    #[test]
    fn test_topological_sort_fails_on_cycle() {
        let mut h = AgentFlowHarness::new();
        let a = h.add_agent(agent("a"));
        let b = h.add_agent(agent("b"));
        h.add_edge(a, b, EdgeKind::Data, "{{ a.out }}".to_string());
        h.add_edge(b, a, EdgeKind::Data, "{{ b.out }}".to_string());

        let result = topological_sort(&h);
        assert!(result.is_none());
    }

    #[test]
    fn test_topological_sort_empty_harness() {
        let h = AgentFlowHarness::new();
        let order = topological_sort(&h);
        assert!(order.is_some());
        assert!(order.unwrap().is_empty());
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
    fn test_resolve_template_multiple_vars() {
        let mut outputs = BTreeMap::new();
        outputs.insert(
            "analyst".to_string(),
            AgentOutput {
                role: "analyst".into(),
                content: "found bug".into(),
                success: true,
            },
        );
        outputs.insert(
            "validator".to_string(),
            AgentOutput {
                role: "validator".into(),
                content: "validated".into(),
                success: true,
            },
        );
        let resolved = resolve_template("{{ analyst.out }} then {{ validator.out }}", &outputs);
        assert_eq!(resolved, "found bug then validated");
    }

    #[test]
    fn test_resolve_template_no_vars() {
        let outputs = BTreeMap::new();
        let resolved = resolve_template("Static prompt", &outputs);
        assert_eq!(resolved, "Static prompt");
    }

    #[test]
    fn test_execution_result_is_success() {
        let result = ExecutionResult {
            outputs: vec![
                AgentOutput {
                    role: "analyst".into(),
                    content: "ok".into(),
                    success: true,
                },
                AgentOutput {
                    role: "validator".into(),
                    content: "validated".into(),
                    success: true,
                },
            ],
            rounds: 1,
        };
        assert!(result.is_success());
    }

    #[test]
    fn test_execution_result_fails_on_one_failure() {
        let result = ExecutionResult {
            outputs: vec![
                AgentOutput {
                    role: "analyst".into(),
                    content: "ok".into(),
                    success: true,
                },
                AgentOutput {
                    role: "validator".into(),
                    content: "failed".into(),
                    success: false,
                },
            ],
            rounds: 1,
        };
        assert!(!result.is_success());
    }
}
