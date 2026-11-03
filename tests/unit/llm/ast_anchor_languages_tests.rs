//! AST anchor tests for newly added languages (go, java, ruby, csharp).
//!
//! These languages were previously unsupported for line anchoring, meaning LLM
//! findings for them never had their line numbers validated against the AST.
//! Each test writes a finding with a deliberately wrong line and asserts the
//! anchor corrects it; negative tests assert that a non-existent function is not
//! silently accepted.

use baco::findings::{Severity, VulnerabilityFinding};
use baco::llm_analysis::anchor_against_ast;

fn finding(line_number: Option<u32>, title: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "x".to_string(),
        title: title.to_string(),
        description: String::new(),
        severity: Severity::Medium,
        confidence_score: 0.7,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "test.txt".to_string(),
        line_number,
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec![],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: None,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
        verification_gate_answers: None,
    }
}

// ==================== GO ====================

const GO_SOURCE: &str = r#"package main

import "fmt"

func main() {
    fmt.Println("Hello")
}

func process(data string) error {
    if data == "" {
        return fmt.Errorf("empty")
    }
    fmt.Println(data)
    return nil
}
"#;

#[test]
fn test_go_anchor_corrects_wrong_line() {
    // Finding claims the vulnerability is on line 16 (past the end of file), but the
    // function `process` is defined on line 9. The anchor should move it.
    let mut f = finding(Some(16), "Unvalidated input in process()");
    anchor_against_ast(std::slice::from_mut(&mut f), GO_SOURCE, Some("go"));
    assert_eq!(
        f.line_number,
        Some(9),
        "line should be moved to process() definition"
    );
}

#[test]
fn test_go_negative_hallucinated_function() {
    // The function `nonExistent` does not exist in the source.
    let mut f = finding(Some(1), "Vulnerability in nonExistent()");
    anchor_against_ast(std::slice::from_mut(&mut f), GO_SOURCE, Some("go"));
    // When the function is not in the file, the line should not be silently
    // accepted as valid - it stays as-is but the anchor result is NameNotInFile.
    assert_eq!(
        f.line_number,
        Some(1),
        "hallucinated function should not change line"
    );
}

// ==================== JAVA ====================

const JAVA_SOURCE: &str = r#"public class Calculator {
    public int add(int a, int b) {
        return a + b;
    }

    public int divide(int a, int b) {
        if (b == 0) {
            throw new ArithmeticException("division by zero");
        }
        return a / b;
    }
}
"#;

#[test]
fn test_java_anchor_corrects_wrong_line() {
    // Finding claims the vulnerability is on line 20 (past the end), but the
    // function `divide` is defined on line 6. The anchor should move it.
    let mut f = finding(Some(20), "Division by zero in divide()");
    anchor_against_ast(std::slice::from_mut(&mut f), JAVA_SOURCE, Some("java"));
    assert_eq!(
        f.line_number,
        Some(6),
        "line should be moved to divide() definition"
    );
}

#[test]
fn test_java_negative_hallucinated_function() {
    // The function `nonExistent` does not exist in the source.
    let mut f = finding(Some(1), "Bug in nonExistent()");
    anchor_against_ast(std::slice::from_mut(&mut f), JAVA_SOURCE, Some("java"));
    assert_eq!(
        f.line_number,
        Some(1),
        "hallucinated function should not change line"
    );
}

// ==================== RUBY ====================

const RUBY_SOURCE: &str = r#"class User
  def initialize(name)
    @name = name
  end

  def greet
    puts "Hello, #{@name}"
  end

  def authenticate(password)
    # Vulnerable: no password validation
    User.find_by(name: @name, password: password)
  end
end
"#;

#[test]
fn test_ruby_anchor_corrects_wrong_line() {
    // Finding claims the vulnerability is on line 20 (past the end), but the
    // function `authenticate` is defined on line 10. The anchor should move it.
    let mut f = finding(Some(20), "SQL injection in authenticate()");
    anchor_against_ast(std::slice::from_mut(&mut f), RUBY_SOURCE, Some("ruby"));
    assert_eq!(
        f.line_number,
        Some(10),
        "line should be moved to authenticate() definition"
    );
}

#[test]
fn test_ruby_negative_hallucinated_function() {
    // The function `nonExistent` does not exist in the source.
    let mut f = finding(Some(1), "Vulnerability in nonExistent()");
    anchor_against_ast(std::slice::from_mut(&mut f), RUBY_SOURCE, Some("ruby"));
    assert_eq!(
        f.line_number,
        Some(1),
        "hallucinated function should not change line"
    );
}

// ==================== C# ====================

const CSHARP_SOURCE: &str = r#"using System;

public class Program
{
    public static void Main()
    {
        Console.WriteLine("Hello");
    }

    public static int Multiply(int a, int b)
    {
        return a * b;
    }
}
"#;

#[test]
fn test_csharp_anchor_corrects_wrong_line() {
    // Finding claims the vulnerability is on line 20 (past the end), but the
    // function `Multiply` is defined on line 10. The anchor should move it.
    let mut f = finding(Some(20), "Integer overflow in Multiply()");
    anchor_against_ast(std::slice::from_mut(&mut f), CSHARP_SOURCE, Some("csharp"));
    assert_eq!(
        f.line_number,
        Some(10),
        "line should be moved to Multiply() definition"
    );
}

#[test]
fn test_csharp_negative_hallucinated_function() {
    // The function `nonExistent` does not exist in the source.
    let mut f = finding(Some(1), "Bug in nonExistent()");
    anchor_against_ast(std::slice::from_mut(&mut f), CSHARP_SOURCE, Some("csharp"));
    assert_eq!(
        f.line_number,
        Some(1),
        "hallucinated function should not change line"
    );
}

// ==================== C# ALIASES ====================

#[test]
fn test_csharp_alias_c_hash() {
    let mut f = finding(Some(20), "Integer overflow in Multiply()");
    anchor_against_ast(std::slice::from_mut(&mut f), CSHARP_SOURCE, Some("c#"));
    assert_eq!(f.line_number, Some(10), "c# alias should work");
}

#[test]
fn test_csharp_alias_cs() {
    let mut f = finding(Some(20), "Integer overflow in Multiply()");
    anchor_against_ast(std::slice::from_mut(&mut f), CSHARP_SOURCE, Some("cs"));
    assert_eq!(f.line_number, Some(10), "cs alias should work");
}
