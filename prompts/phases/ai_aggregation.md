# AI Aggregation Phase Prompt

Aggregate security findings into an executive summary and risk assessment.

Input: %%FINDINGS_LIST%% (JSON array of all vulnerabilities)
Project type: %%PROJECT_TYPE%%
Languages: %%LANGUAGES%%
Total files: %%TOTAL_FILES%%
Scan date: %%SCAN_DATE%%

Generate:
1. Executive Summary:
   - Total vulnerabilities by severity
   - Critical findings requiring immediate attention
   - Most affected components/modules

2. Risk Assessment:
   - Overall risk level: critical|high|medium|low
   - Attack surface analysis
   - Remediation priority ranking

3. Recommendations:
   - Immediate fixes (critical/high severity)
   - Long-term improvements
   - Security testing recommendations

Return JSON:
{
  "executive_summary": "100 word summary...",
  "risk_level": "high",
  "total_vulnerabilities": 42,
  "by_severity": {
    "critical": 2,
    "high": 8,
    "medium": 15,
    "low": 17
  },
  "critical_findings": [
    {
      "title": "...",
      "file": "...",
      "line": 123,
      "severity": "critical",
      "business_impact": "..."
    }
  ],
  "remediation_priority": [
    {"order": 1, "title": "...", "effort": "low|medium|high"},
    ...
  ],
  "recommendations": ["recommendation 1", "recommendation 2", ...]
}
