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
