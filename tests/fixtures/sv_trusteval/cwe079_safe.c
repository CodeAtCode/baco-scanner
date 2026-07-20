/*
 * SV-TrustEval-C Fixture: CWE-79 Cross-Site Scripting - XSS (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: HTML entity escaping before output
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 256
#define MAX_OUTPUT 1024  /* Larger for escaped content */

/* Helper: Escape HTML special characters */
void html_escape(const char *input, char *output, size_t output_size) {
    size_t j = 0;
    
    for (size_t i = 0; input[i] && j < output_size - 5; i++) {
        switch (input[i]) {
            case '<':
                if (j + 4 < output_size) {
                    strcpy(&output[j], "&lt;");
                    j += 4;
                }
                break;
            case '>':
                if (j + 4 < output_size) {
                    strcpy(&output[j], "&gt;");
                    j += 4;
                }
                break;
            case '&':
                if (j + 5 < output_size) {
                    strcpy(&output[j], "&amp;");
                    j += 5;
                }
                break;
            case '"':
                if (j + 6 < output_size) {
                    strcpy(&output[j], "&quot;");
                    j += 6;
                }
                break;
            default:
                output[j++] = input[i];
                break;
        }
    }
    output[j] = '\0';
}

/* Safe: HTML-escaped reflection */
void render_greeting_safe(const char *user_input) {
    char escaped[MAX_INPUT * 5];  /* Worst case: each char becomes 5 chars */
    char output[MAX_OUTPUT];
    
    /* SAFE: Escape HTML special characters */
    html_escape(user_input, escaped, sizeof(escaped));
    
    snprintf(output, sizeof(output),
        "<html><body><h1>Welcome, %s!</h1></body></html>",
        escaped);
    
    printf("Content-Type: text/html\n\n");
    printf("%s\n", output);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    
    render_greeting_safe(argv[1]);
    return 0;
}