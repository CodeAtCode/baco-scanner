/*
 * SV-TrustEval-C Fixture: CWE-78 OS Command Injection (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: User input passed directly to system()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PATH 256

/* Vulnerable: User input directly passed to system() */
int ping_host_vulnerable(const char *host) {
    char command[MAX_PATH];
    
    /* VULNERABLE: No sanitization - command injection possible */
    snprintf(command, sizeof(command), "ping -c 1 %s", host);
    
    printf("Executing: %s\n", command);
    
    /* VULNERABLE: system() with unsanitized input */
    return system(command);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <host>\n", argv[0]);
        return 1;
    }
    
    return ping_host_vulnerable(argv[1]);
}