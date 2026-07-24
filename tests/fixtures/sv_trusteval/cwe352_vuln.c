/*
 * SV-TrustEval-C Fixture: CWE-352 Cross-Site Request Forgery (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: No CSRF token validation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SESSION 64
#define MAX_ACTION 32

/* Vulnerable: No token validation on state-changing operation */
int transfer_funds_vulnerable(const char *session_id, const char *amount) {
    char buffer[256];
    
    /* VULNERABLE: No CSRF token check */
    /* Any request with valid session is accepted */
    
    snprintf(buffer, sizeof(buffer),
        "TRANSFER session=%s amount=%s",
        session_id, amount);
    
    printf("Processing: %s\n", buffer);
    
    /* VULNERABLE: Process without token validation */
    /* In real code: execute transfer without checking origin */
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <session_id> <amount>\n", argv[0]);
        return 1;
    }
    
    return transfer_funds_vulnerable(argv[1], argv[2]);
}