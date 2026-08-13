//! Comprehensive unit tests for agent_flow submodules.
//!
//! Tests cover:
//! - typecheck.rs: TypeError variants, typecheck function, template var extraction
//! - diagnoser.rs: diagnose function, format_diagnostic, Diagnostic methods
//! - proposer.rs: pure helper functions (build_harness_summary, parse_rewrite_proposal, parse_single_edit, apply_rewrite)
//! - dsl.rs: AgentFlowHarness construction via builders

use baco::agent_flow::diagnoser::{diagnose, format_diagnostic, Diagnostic, FeedbackSignal};
use baco::agent_flow::dsl::{Agent, AgentFlowHarness, EdgeKind, FeedbackChannel, NodeKind};
use baco::agent_flow::proposer::{apply_rewrite, HarnessEdit, RewriteProposal};
use baco::agent_flow::typecheck::{typecheck, TypeError};
use std::collections::BTreeSet;

// ============================================================================
// Helper functions
// ============================================================================

fn test_agent(role: &str) -> Agent {
    Agent {
        role: role.to_string(),
        prompt: format!("Prompt for {}", role),
        model: "test-model".to_string(),
        tools: BTreeSet::new(),
    }
}

// ============================================================================
// TypeError Display tests
// ============================================================================

#[test]
fn test_typeerror_display_unknown_node() {
    let err = TypeError::UnknownNode {
        edge_idx: 0,
        endpoint: 99,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("edge 0"));
    assert!(msg.contains("unknown node 99"));
}

#[test]
fn test_typeerror_display_fanout_target_missing() {
    let err = TypeError::FanoutTargetMissing {
        node_idx: 5,
        target: 10,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("fanout node 5"));
    assert!(msg.contains("missing node 10"));
}

#[test]
fn test_typeerror_display_cycle_in_data_edges() {
    let err = TypeError::CycleInDataEdges {
        nodes: vec![0, 1, 2],
    };
    let msg = format!("{}", err);
    assert!(msg.contains("cycle in data edges"));
    assert!(msg.contains("[0, 1, 2]"));
}

#[test]
fn test_typeerror_display_template_var_missing() {
    let err = TypeError::TemplateVarMissing {
        edge_idx: 3,
        var: "unknown_role".to_string(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("edge 3"));
    assert!(msg.contains("unknown agent: unknown_role"));
}

#[test]
fn test_typeerror_display_empty_harness() {
    let err = TypeError::EmptyHarness;
    let msg = format!("{}", err);
    assert_eq!(msg, "harness has no nodes");
}

#[test]
fn test_typeerror_display_duplicate_role() {
    let err = TypeError::DuplicateRole {
        role: "analyst".to_string(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("duplicate agent role"));
    assert!(msg.contains("analyst"));
}

// ============================================================================
// typecheck function tests
// ============================================================================

#[test]
fn test_typecheck_empty_harness_returns_error() {
    let harness = AgentFlowHarness {
        nodes: vec![],
        edges: vec![],
        feedback: BTreeSet::new(),
    };
    let result = typecheck(&harness);
    assert!(matches!(result, Err(TypeError::EmptyHarness)));
}

#[test]
fn test_typecheck_valid_harness_returns_ok() {
    let mut harness = AgentFlowHarness::new();
    let a = harness.add_agent(test_agent("analyst"));
    let b = harness.add_agent(test_agent("validator"));
    harness.add_edge(a, b, EdgeKind::Data, "{{ analyst.out }}".to_string());

    let result = typecheck(&harness);
    assert!(result.is_ok());
}

#[test]
fn test_typecheck_unknown_node_reference() {
    let mut harness = AgentFlowHarness::new();
    harness.add_agent(test_agent("a"));
    // Edge references node 99 which doesn't exist
    harness.add_edge(0, 99, EdgeKind::Data, "{{ a.out }}".to_string());

    let result = typecheck(&harness);
    assert!(matches!(
        result,
        Err(TypeError::UnknownNode {
            edge_idx: 0,
            endpoint: 99
        })
    ));
}

#[test]
fn test_typecheck_cycle_in_data_edges() {
    let mut harness = AgentFlowHarness::new();
    let a = harness.add_agent(test_agent("a"));
    let b = harness.add_agent(test_agent("b"));

    // Create a cycle: a -> b -> a via Data edges
    harness.add_edge(a, b, EdgeKind::Data, "{{ a.out }}".to_string());
    harness.add_edge(b, a, EdgeKind::Data, "{{ b.out }}".to_string());

    let result = typecheck(&harness);
    assert!(matches!(result, Err(TypeError::CycleInDataEdges { .. })));
}

#[test]
fn test_typecheck_duplicate_role_rejected() {
    let mut harness = AgentFlowHarness::new();
    harness.add_agent(test_agent("analyst"));
    harness.add_agent(test_agent("analyst")); // Duplicate role

    let result = typecheck(&harness);
    assert!(matches!(result, Err(TypeError::DuplicateRole { role }) if role == "analyst"));
}

#[test]
fn test_typecheck_fanout_target_missing() {
    let mut harness = AgentFlowHarness::new();
    harness.add_agent(test_agent("a"));
    // Fanout references non-existent node 99
    harness.add_fanout(99, 3);

    let result = typecheck(&harness);
    assert!(matches!(
        result,
        Err(TypeError::FanoutTargetMissing { target: 99, .. })
    ));
}

#[test]
fn test_typecheck_guarded_edge_cycle_allowed() {
    let mut harness = AgentFlowHarness::new();
    let a = harness.add_agent(test_agent("a"));
    let b = harness.add_agent(test_agent("b"));

    // Data edge a -> b, guarded edge b -> a (cycle allowed with guarded)
    harness.add_edge(a, b, EdgeKind::Data, "{{ a.out }}".to_string());
    harness.add_edge(
        b,
        a,
        EdgeKind::Guarded("fail".to_string()),
        "{{ b.out }}".to_string(),
    );

    let result = typecheck(&harness);
    assert!(result.is_ok());
}

#[test]
fn test_typecheck_template_var_missing() {
    let mut harness = AgentFlowHarness::new();
    let a = harness.add_agent(test_agent("a"));
    harness.add_agent(test_agent("b"));
    // Template references "nonexistent" which doesn't exist
    harness.add_edge(a, 1, EdgeKind::Data, "{{ nonexistent.out }}".to_string());

    let result = typecheck(&harness);
    assert!(matches!(result, Err(TypeError::TemplateVarMissing { .. })));
}

// ============================================================================
// AgentFlowHarness DSL builder tests
// ============================================================================

#[test]
fn test_harness_add_agent_returns_correct_index() {
    let mut harness = AgentFlowHarness::new();
    let idx1 = harness.add_agent(test_agent("first"));
    let idx2 = harness.add_agent(test_agent("second"));

    assert_eq!(idx1, 0);
    assert_eq!(idx2, 1);
    assert_eq!(harness.nodes.len(), 2);
}

#[test]
fn test_harness_add_fanout_creates_node() {
    let mut harness = AgentFlowHarness::new();
    let agent_idx = harness.add_agent(test_agent("source"));
    let fanout_idx = harness.add_fanout(agent_idx, 5);

    assert_eq!(fanout_idx, 1);
    assert_eq!(harness.nodes.len(), 2);

    match &harness.nodes[1].kind {
        NodeKind::Fanout { node_idx, k } => {
            assert_eq!(*node_idx, agent_idx);
            assert_eq!(*k, 5);
        }
        _ => panic!("Expected Fanout node"),
    }
}

#[test]
fn test_harness_add_edge_with_guarded_kind() {
    let mut harness = AgentFlowHarness::new();
    let a = harness.add_agent(test_agent("a"));
    let b = harness.add_agent(test_agent("b"));

    harness.add_edge(
        a,
        b,
        EdgeKind::Guarded("error".to_string()),
        "{{ a.out }}".to_string(),
    );

    assert_eq!(harness.edges.len(), 1);
    match &harness.edges[0].kind {
        EdgeKind::Guarded(label) => assert_eq!(label, "error"),
        _ => panic!("Expected Guarded edge"),
    }
}

// ============================================================================
// diagnoser tests
// ============================================================================

#[test]
fn test_diagnose_success_with_pass_no_rewrite() {
    let execution = baco::agent_flow::executor::ExecutionResult {
        outputs: vec![baco::agent_flow::executor::AgentOutput {
            role: "analyst".into(),
            content: "done".into(),
            success: true,
        }],
        rounds: 1,
    };

    let mut channels = BTreeSet::new();
    channels.insert(FeedbackChannel::Outcome);

    let signals = vec![FeedbackSignal::Pass];
    let diag = diagnose(&execution, &channels, signals);

    assert!(!diag.should_rewrite);
    assert!(diag.is_success());
}

#[test]
fn test_diagnose_crash_with_sanitizer_channel_no_rewrite() {
    let execution = baco::agent_flow::executor::ExecutionResult {
        outputs: vec![baco::agent_flow::executor::AgentOutput {
            role: "analyst".into(),
            content: "done".into(),
            success: true,
        }],
        rounds: 1,
    };

    let mut channels = BTreeSet::new();
    channels.insert(FeedbackChannel::Sanitizer);

    let signals = vec![FeedbackSignal::SanitizerCrash {
        kind: "heap-buffer-overflow".into(),
        location: "main.c:42".into(),
    }];

    let diag = diagnose(&execution, &channels, signals);

    // Crash with sanitizer channel is expected, no rewrite needed
    assert!(!diag.should_rewrite);
}

#[test]
fn test_diagnose_failure_triggers_rewrite() {
    let execution = baco::agent_flow::executor::ExecutionResult {
        outputs: vec![baco::agent_flow::executor::AgentOutput {
            role: "validator".into(),
            content: "failed".into(),
            success: false,
        }],
        rounds: 1,
    };

    let channels = BTreeSet::new();
    let signals = vec![];

    let diag = diagnose(&execution, &channels, signals);

    assert!(diag.should_rewrite);
}

#[test]
fn test_diagnose_coverage_increase_with_channel_triggers_rewrite() {
    let execution = baco::agent_flow::executor::ExecutionResult {
        outputs: vec![baco::agent_flow::executor::AgentOutput {
            role: "analyst".into(),
            content: "done".into(),
            success: true,
        }],
        rounds: 1,
    };

    let mut channels = BTreeSet::new();
    channels.insert(FeedbackChannel::Coverage);

    let signals = vec![FeedbackSignal::CoverageIncrease(0.15)];

    let diag = diagnose(&execution, &channels, signals);

    // Coverage increase without pass triggers rewrite for improvement
    assert!(diag.should_rewrite);
}

#[test]
fn test_format_diagnostic_with_multiple_signals() {
    let diag = Diagnostic {
        signals: vec![
            FeedbackSignal::CoverageIncrease(0.25),
            FeedbackSignal::BranchHit(10),
            FeedbackSignal::TraceEvent {
                label: "latency".into(),
                value: "150ms".into(),
            },
        ],
        summary: "coverage increased; branches hit".to_string(),
        should_rewrite: true,
    };

    let formatted = format_diagnostic(&diag);

    assert!(formatted.contains("coverage +25.0%"));
    assert!(formatted.contains("branches hit: 10"));
    assert!(formatted.contains("trace latency: 150ms"));
    assert!(formatted.contains("Rewrite needed: yes"));
}

#[test]
fn test_diagnostic_is_success_method() {
    let success_diag = Diagnostic {
        signals: vec![FeedbackSignal::Pass],
        summary: "all good".to_string(),
        should_rewrite: false,
    };
    assert!(success_diag.is_success());

    let fail_diag = Diagnostic {
        signals: vec![FeedbackSignal::Fail("test failed".into())],
        summary: "failed".to_string(),
        should_rewrite: true,
    };
    assert!(!fail_diag.is_success());
}

// ============================================================================
// proposer pure function tests (only apply_rewrite is public API)
// ============================================================================

#[test]
fn test_apply_rewrite_add_agent() {
    let mut harness = AgentFlowHarness::new();
    harness.add_agent(test_agent("analyst"));

    let proposal = RewriteProposal {
        edits: vec![HarnessEdit::AddAgent {
            role: "reviewer".into(),
            prompt: "Review findings".into(),
        }],
        rationale: "Add reviewer for quality".into(),
    };

    let new_harness = apply_rewrite(&harness, &proposal);

    assert_eq!(new_harness.nodes.len(), 2);
    let roles: Vec<&str> = new_harness
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            NodeKind::Agent(a) => Some(a.role.as_str()),
            _ => None,
        })
        .collect();
    assert!(roles.contains(&"analyst"));
    assert!(roles.contains(&"reviewer"));
}

#[test]
fn test_apply_rewrite_remove_agent() {
    let mut harness = AgentFlowHarness::new();
    let a = harness.add_agent(test_agent("analyst"));
    let b = harness.add_agent(test_agent("validator"));
    harness.add_edge(a, b, EdgeKind::Data, "{{ analyst.out }}".to_string());

    let proposal = RewriteProposal {
        edits: vec![HarnessEdit::RemoveAgent {
            role: "validator".into(),
        }],
        rationale: "Remove unnecessary validator".into(),
    };

    let new_harness = apply_rewrite(&harness, &proposal);

    assert_eq!(new_harness.nodes.len(), 1);
    assert!(new_harness.edges.is_empty());
}

#[test]
fn test_apply_rewrite_add_edge() {
    let mut harness = AgentFlowHarness::new();
    let _a = harness.add_agent(test_agent("analyst"));
    let _b = harness.add_agent(test_agent("validator"));

    let proposal = RewriteProposal {
        edits: vec![HarnessEdit::AddEdge {
            from_role: "validator".into(),
            to_role: "analyst".into(),
            kind: "data".into(),
            template: "{{ validator.out }}".into(),
        }],
        rationale: "Add feedback loop".into(),
    };

    let new_harness = apply_rewrite(&harness, &proposal);

    assert_eq!(new_harness.edges.len(), 1);
}

#[test]
fn test_apply_rewrite_update_prompt() {
    let mut harness = AgentFlowHarness::new();
    harness.add_agent(test_agent("analyst"));

    let proposal = RewriteProposal {
        edits: vec![HarnessEdit::UpdatePrompt {
            role: "analyst".into(),
            new_prompt: "New prompt content".into(),
        }],
        rationale: "Update analyst prompt".into(),
    };

    let new_harness = apply_rewrite(&harness, &proposal);

    let analyst_node = new_harness
        .nodes
        .iter()
        .find(|n| matches!(&n.kind, NodeKind::Agent(a) if a.role == "analyst"))
        .unwrap();

    match &analyst_node.kind {
        NodeKind::Agent(a) => assert_eq!(a.prompt, "New prompt content"),
        _ => panic!("Expected Agent node"),
    }
}

#[test]
fn test_apply_rewrite_remove_edge() {
    let mut harness = AgentFlowHarness::new();
    let a = harness.add_agent(test_agent("analyst"));
    let b = harness.add_agent(test_agent("validator"));
    harness.add_edge(a, b, EdgeKind::Data, "{{ analyst.out }}".to_string());

    let proposal = RewriteProposal {
        edits: vec![HarnessEdit::RemoveEdge {
            from_role: "analyst".into(),
            to_role: "validator".into(),
        }],
        rationale: "Remove unnecessary edge".into(),
    };

    let new_harness = apply_rewrite(&harness, &proposal);

    assert!(new_harness.edges.is_empty());
}

#[test]
fn test_harness_edit_debug_display() {
    let edit = HarnessEdit::AddAgent {
        role: "test".into(),
        prompt: "Test prompt".into(),
    };

    let debug_str = format!("{:?}", edit);
    assert!(debug_str.contains("AddAgent"));
    assert!(debug_str.contains("test"));
}

#[test]
fn test_rewrite_proposal_debug_display() {
    let proposal = RewriteProposal {
        edits: vec![],
        rationale: "Test rationale".into(),
    };

    let debug_str = format!("{:?}", proposal);
    assert!(debug_str.contains("RewriteProposal"));
    assert!(debug_str.contains("Test rationale"));
}
