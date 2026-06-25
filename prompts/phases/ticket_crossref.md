# Ticket Cross-Reference Phase Prompt

Search for this vulnerability in ticket systems and correlate with existing issues.

Vulnerability title: %%VULNERABILITY_TITLE%%
File path: %%FILE_PATH%%
Description: %%VULNERABILITY_DESCRIPTION%%

Search strategies:
1. Search ticket IDs by vulnerability title keywords
2. Search by file path in commit history
3. Search by CWE classification
4. Search by affected function names

Ticket systems to search:
- %%TICKET_SYSTEMS%% (GitHub, GitLab, Jira, etc.)

Return JSON array with matches:
[
  {
    "system": "github|gitlab|jira|custom",
    "ticket_id": "TICKET-123",
    "title": "related ticket title",
    "url": "https://example.com/issue/123",
    "confidence": 0.0-1.0
  }
]

Note: Return empty array [] if no matches found.
