# Cross-File Analysis Phase Prompt

Analyze cross-file references and data flow to understand vulnerability propagation.

Input vulnerabilities:
%%VULNERABILITY_LIST%% (JSON array of finding objects)

Analysis tasks:
1. Identify shared functions that process vulnerable data
2. Trace data flow from vulnerable entry points to dangerous sinks
3. Find common patterns across multiple files
4. Detect potential RCE via inclusion chains

Return JSON array with cross-references:
[
  {
    "source_file": "a/b/c.c",
    "target_file": "x/y/z.c",
    "connection_type": "shared_function|data_flow|include_dependency",
    "explanation": "how they are related",
    "risk_increase": "low|medium|high"
  }
]
