# Confidence Scoring Phase Prompt

Recalculate confidence scores for security vulnerability findings.

For each finding, consider:
1. Evidence quality:
   - Static analysis (Semgrep): moderate confidence
   - LLM analysis: low-to-moderate (needs verification)
   - Verified by human: high confidence
   - Confirmed false positive: 0.0

2. Source reliability:
   - Multiple independent sources: higher confidence
   - Single source: lower confidence

3. Mitigating factors:
   - Presence of sanitization: reduces confidence
   - Use in non-critical code path: reduces confidence
   - Known false positive pattern: low confidence

Input findings: %%FINDINGS_LIST%%

Return JSON array with recalculated scores:
[
  {
    "id": "unique-finding-id",
    "original_score": 0.0-1.0,
    "recalculated_score": 0.0-1.0,
    "evidence_sources": ["semgrep", "llm_analysis"],
    "adjustment_reason": "reason for score change"
  }
]
