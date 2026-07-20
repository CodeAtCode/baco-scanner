# LLM Verification Phase Prompt

Verify if this security vulnerability finding is a true positive, false positive, or needs review.

Finding: %%FINDING_TITLE%%
Location: %%FILE_PATH%%:%%LINE_NUMBER%%
Description: %%VULNERABILITY_DESCRIPTION%%
Sources: %%SOURCE_LIST%%

Analysis criteria:
- Is the vulnerable code actually exploitable?
- Are there mitigating factors (sanitization, sandboxing)?
- Is this a known false positive pattern?
- Does the code actually execute at runtime?

Return JSON with format:
{
  "verification_status": "confirmed|false_positive|needs_review",
  "verification_notes": "detailed reasoning",
  "confidence": 0.0-1.0,
  "mitigating_factors": ["optional mitigation 1", ...],
  "related_patterns": ["optional pattern 1", ...]
}

## Triage Step

When a finding is marked as `NeedsReview`, invoke the triage filter for additional analysis:

1. **Triage Prompt**: Send a zero-shot prompt asking "Is this finding a true positive or false positive?"
2. **Expected Output**: JSON with `{"verdict": "true_positive"|"false_positive", "confidence": 0.0-1.0, "reasoning": "..."}`
3. **Integration**:
   - If triage returns `false_positive`: Set status to `FalsePositive`, add reasoning to `verification_notes`
   - If triage returns `true_positive`: Keep `Confirmed` status, boost confidence by +0.10
   - On parse failure: Fall back gracefully to `NeedsReview` status

## Confidence Refinement Factors

- `TriageTruePositive`: +0.10 boost when triage confirms true positive
- `TriageFalsePositive`: -0.25 penalty when triage identifies false positive
