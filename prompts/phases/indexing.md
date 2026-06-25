# Indexing Phase Prompt

Analyze the project structure at %%PROJECT_PATH%%. Create a comprehensive index of all source code files. Consider:

- File extensions: %%FILE_EXTENSIONS%%
- Languages to index: %%LANGUAGES%%
- Maximum file size: %%MAX_FILE_SIZE%% bytes
- Exclude paths: %%EXCLUDE_PATHS%%

Output format: JSON array with file paths, sizes, and language detection.
Result: [
  {"path": "relative/path", "size": bytes, "language": "c/cpp/python"},
  ...
]
