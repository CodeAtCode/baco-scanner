//! Pattern DSL for MoCQ rule synthesis (P3.1).
//!
//! Intermediate representation between LLM proposals and Semgrep YAML emission.
//! A pattern specifies: what to match, what to constrain, and metadata.

/// Where taint originates: a function return value or a parameter at position N.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintSource {
    Return,
    Param(usize),
}

/// Where taint flows to: a function argument at position N.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSink {
    pub function: String,
    pub arg_position: usize,
}

/// A single pattern: match function calls and constrain taint flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub id: String,
    pub cwe: String,
    pub source: TaintSource,
    pub sink: TaintSink,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// Parse an LLM-produced pattern spec line into a `Pattern`.
///
/// Expected format (one pattern per line):
/// `PATTERN <id> CWE-<n> <source> -> <sink_func>[<arg_pos>] <severity>`
///
/// Examples:
///   `PATTERN p1 CWE-89 return -> mysql_query[0] HIGH`
///   `PATTERN p2 CWE-79 param[0] -> htmlspecialchars[1] MEDIUM`
pub fn parse_pattern(line: &str) -> Result<Pattern, PatternError> {
    let line = line.trim();
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 7 || parts[0] != "PATTERN" {
        return Err(PatternError::Malformed(
            "expected: PATTERN <id> CWE-<n> <source> -> <sink_func>[<pos>] <severity>".into(),
        ));
    }

    let id = parts[1].to_string();
    let cwe = parts[2].to_string();

    let source = match parts[3] {
        "return" => TaintSource::Return,
        s if s.starts_with("param[") && s.ends_with(']') => {
            let n: usize = s[6..s.len() - 1]
                .parse()
                .map_err(|_| PatternError::Malformed(format!("invalid param index: {}", s)))?;
            TaintSource::Param(n)
        }
        s => {
            return Err(PatternError::Malformed(format!(
                "invalid taint source: {}",
                s
            )))
        }
    };

    if parts[4] != "->" {
        return Err(PatternError::Malformed(
            "expected '->' between source and sink".into(),
        ));
    }

    let sink_str = parts[5];
    let bracket_start = sink_str
        .find('[')
        .ok_or_else(|| PatternError::Malformed(format!("missing [ in sink: {}", sink_str)))?;
    let bracket_end = sink_str
        .find(']')
        .ok_or_else(|| PatternError::Malformed(format!("missing ] in sink: {}", sink_str)))?;
    let function = sink_str[..bracket_start].to_string();
    let arg_position: usize = sink_str[bracket_start + 1..bracket_end]
        .parse()
        .map_err(|_| PatternError::Malformed(format!("invalid arg position in: {}", sink_str)))?;

    let sink = TaintSink {
        function,
        arg_position,
    };

    let severity = match parts[6] {
        "LOW" => Severity::Low,
        "MEDIUM" => Severity::Medium,
        "HIGH" => Severity::High,
        "CRITICAL" => Severity::Critical,
        s => return Err(PatternError::Malformed(format!("invalid severity: {}", s))),
    };

    Ok(Pattern {
        id,
        cwe,
        source,
        sink,
        severity,
    })
}

#[derive(Debug, Clone)]
pub enum PatternError {
    Malformed(String),
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(msg) => write!(f, "pattern parse error: {}", msg),
        }
    }
}

impl std::error::Error for PatternError {}
