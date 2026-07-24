/*
 * SV-TrustEval-C Fixture: CWE-134 Uncontrolled Format String (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: User input used as format string
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 256

/* Vulnerable: User input as format string */
void log_message_vulnerable(const char *user_input) {
    char buffer[BUFFER_SIZE];
    
    /* VULNERABLE: User input directly used as format string */
    /* Attacker can use %s, %x, %n to read/write memory */
    printf(user_input);
    
    /* Also vulnerable: */
    snprintf(buffer, sizeof(buffer), user_input);
    printf("Logged: %s\n", buffer);
}

/* Vulnerable: Format string in error message */
void report_error_vulnerable(const char *error_msg) {
    /* VULNERABLE: Error message from untrusted source used as format string */
    fprintf(stderr, error_msg);
}

int main(int argc, char *argv[]) {
    const char *input = "Normal message";
    
    if (argc > 1) {
        input = argv[1];
    }
    
    /* VULNERABLE: If input contains format specifiers, crash or leak */
    log_message_vulnerable(input);
    report_error_vulnerable(input);
    
    return 0;
}