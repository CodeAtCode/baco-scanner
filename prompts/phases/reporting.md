# Reporting Phase Prompt

Generate security scan report for %%PROJECT_NAME%%.

Scan metadata:
- Date: %%SCAN_DATE%%
- Scanned files: %%FILES_COUNT%%
- Total vulnerabilities found: %%TOTAL_FINDINGS%%
- Tools used: %%TOOLS_USED%%
- Scan duration: %%SCAN_DURATION%%

Report sections to include:
1. Executive Summary (for management)
2. Critical Findings (detailed with remediation)
3. Security Recommendations
4. Appendix: All findings with JSON data

Output formats:
- JSON: Structured data for API consumption
- HTML: Human-readable report with styling
- SARIF: Standard format for CI/CD integration

Report requirements:
- Clear severity indicators
- Actionable remediation steps
- Reference to CWE IDs
- File locations with line numbers
- Confidence scores

Generate report content in the specified format.
