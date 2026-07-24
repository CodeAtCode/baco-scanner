# LLM Verification Phase Prompt

Verify if this security vulnerability finding is a true positive, false positive, or needs review.

Finding: %%FINDING_TITLE%%
Location: %%FILE_PATH%%:%%LINE_NUMBER%%
Description: %%VULNERABILITY_DESCRIPTION%%
Sources: %%SOURCE_LIST%%

## B1: 7-Question Gate Triage

Each finding must pass the following structured 7-question gate. Answer each question with YES/NO/UNKNOWN:

1. **Reachability**: Can the vulnerable function be reached from user input or external interface? (YES/NO/UNKNOWN)
2. **Controllability**: Does the attacker control the relevant input parameter? (YES/NO/UNKNOWN)
3. **Preconditions**: Are there sanitization or validation checks that block exploitation? (YES=blocked, NO=not blocked, UNKNOWN)
4. **Impact**: What is the concrete security impact if exploited? (YES=concrete impact, NO=no impact, UNKNOWN)
5. **Context**: Is the code in a test file, example, or production path? (YES=production, NO=test/example, UNKNOWN)
6. **Evidence**: Is there code evidence (not just pattern match) supporting this finding? (YES=confirmed, NO=no evidence, UNKNOWN)
7. **Confidence**: Given all answers above, is this a true positive? (YES/NO/UNKNOWN)

**Gate Logic**:
- If Q1 (Reachability) = NO → KILL finding (not reachable)
- If Q2 (Controllability) = NO → KILL finding (not controllable)
- If Q3 (Preconditions) = YES → KILL finding (blocked by sanitization)
- If Q1-Q3 all pass AND Q4-Q7 all = YES/CONFIRMED → PASS finding
- Otherwise → NEEDS_REVIEW

## B2: Concrete Impact Proof Requirement

You MUST provide a concrete impact scenario:
- Example: "Attacker sends `; rm -rf /` in the `name` parameter, which reaches `system()` at line 42"
- If the impact is theoretical ("could potentially lead to..."), downgrade the finding
- The scenario must show the EXACT attack vector and the CONSEQUENCE

Return JSON with format:
{
  "seven_question_gate": {
    "reachability": "yes|no|unknown",
    "controllability": "yes|no|unknown",
    "preconditions": "yes|no|unknown",
    "impact": "yes|no|unknown",
    "context": "yes|no|unknown",
    "evidence": "yes|no|unknown",
    "confidence": "yes|no|unknown"
  },
  "concrete_impact_proof": {
    "attack_vector": "exact attack scenario with input and location",
    "consequence": "specific security impact",
    "is_theoretical": true|false
  },
  "triage_verdict": "pass|kill|downgrade|needs_review",
  "verification_status": "confirmed|false_positive|needs_review",
  "verification_notes": "detailed reasoning including gate answers",
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
