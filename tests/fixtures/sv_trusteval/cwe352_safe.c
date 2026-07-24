/*
 * SV-TrustEval-C Fixture: CWE-352 Cross-Site Request Forgery (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: CSRF token validation required
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SESSION 64
#define MAX_TOKEN 64
#define MAX_ACTION 32

/* Simulated token store (in real code, session-based) */
static const char *valid_tokens[] = {
    "abc123token",
    "def456token",
    NULL
};

/* Helper: Validate CSRF token */
static int is_valid_token(const char *token) {
    for (int i = 0; valid_tokens[i] != NULL; i++) {
        if (strcmp(token, valid_tokens[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Safe: Require valid CSRF token */
int transfer_funds_safe(const char *session_id, const char *amount, const char *csrf_token) {
    char buffer[320];
    
    /* SAFE: Validate CSRF token before processing */
    if (csrf_token == NULL || !is_valid_token(csrf_token)) {
        fprintf(stderr, "Invalid CSRF token - request rejected\n");
        return 1;
    }
    
    snprintf(buffer, sizeof(buffer),
        "TRANSFER session=%s amount=%s token=%s",
        session_id, amount, csrf_token);
    
    printf("Processing: %s\n", buffer);
    
    /* SAFE: Token validated, now process */
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <session_id> <amount> <csrf_token>\n", argv[0]);
        return 1;
    }
    
    return transfer_funds_safe(argv[1], argv[2], argv[3]);
}