/*
 * SV-TrustEval-C Fixture: CWE-79 Cross-Site Scripting - XSS (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: User input reflected directly into HTML without escaping
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 256
#define MAX_OUTPUT 512

/* Vulnerable: Direct reflection of user input to HTML */
void render_greeting_vulnerable(const char *user_input) {
    char output[MAX_OUTPUT];
    
    /* VULNERABLE: No escaping - malicious script executes in browser */
    snprintf(output, sizeof(output),
        "<html><body><h1>Welcome, %s!</h1></body></html>",
        user_input);
    
    printf("Content-Type: text/html\n\n");
    printf("%s\n", output);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    
    render_greeting_vulnerable(argv[1]);
    return 0;
}