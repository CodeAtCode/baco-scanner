/*
 * SV-TrustEval-C Fixture: CWE-78 OS Command Injection (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: Input validation and allowlist pattern
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_HOST 64

/* Helper: Validate hostname contains only safe characters */
static int is_valid_hostname(const char *host) {
    size_t len = strlen(host);
    if (len == 0 || len > MAX_HOST) {
        return 0;
    }
    
    /* Allow only alphanumeric and dots (hostname pattern) */
    for (size_t i = 0; i < len; i++) {
        char c = host[i];
        if (!isalnum(c) && c != '.' && c != '-') {
            return 0;
        }
    }
    return 1;
}

/* Safe: Validate input before using in command */
int ping_host_safe(const char *host) {
    char command[MAX_HOST + 16];
    
    /* SAFE: Validate input against allowlist pattern */
    if (!is_valid_hostname(host)) {
        fprintf(stderr, "Invalid hostname: contains unsafe characters\n");
        return 1;
    }
    
    snprintf(command, sizeof(command), "ping -c 1 %s", host);
    printf("Executing: %s\n", command);
    
    return system(command);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <host>\n", argv[0]);
        return 1;
    }
    
    return ping_host_safe(argv[1]);
}