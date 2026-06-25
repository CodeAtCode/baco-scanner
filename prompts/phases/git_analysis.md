# Git Analysis Phase Prompt

Analyze Git history for the specified file to understand vulnerability evolution.

File path: %%FILE_PATH%%
Line number: %%LINE_NUMBER%% (if known, else analyze entire file)

Analysis tasks:
1. Find commits that introduced the suspicious code pattern
2. Track evolution of the vulnerable function
3. Identify related security improvements
4. Note author commit history on this file

Git commands to run:
- git log --follow -- %%FILE_PATH%%
- git blame %%FILE_PATH%%
- git log -p -- %%FILE_PATH%% (context around line)

Return JSON array with commits:
[
  {
    "commit_hash": "abc123def",
    "author": "Author Name",
    "date": "2024-01-15T10:30:00Z",
    "message": "commit message",
    "role": "introduced|modified|reviewed|security_related"
  }
]
