/*
 * SV-TrustEval-C Fixture: CWE-134 Uncontrolled Format String (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: Use %s format specifier with user input as argument
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 256

/* Safe: Use format specifier with user input as argument */
void log_message_safe(const char *user_input) {
    char buffer[BUFFER_SIZE];
    
    /* SAFE: User input as argument, not format string */
    printf("%s", user_input);
    
    /* SAFE: Fixed format string with user input as argument */
    snprintf(buffer, sizeof(buffer), "%s", user_input);
    printf("Logged: %s\n", buffer);
}

/* Safe: Fixed format string for error reporting */
void report_error_safe(const char *error_msg) {
    /* SAFE: Use %s format specifier */
    fprintf(stderr, "%s", error_msg);
}

/* Safe: Sanitize input to remove format specifiers */
static void sanitize_format_string(const char *input, char *output, size_t output_size) {
    size_t j = 0;
    for (size_t i = 0; input[i] != '\0' && j < output_size - 1; i++) {
        if (input[i] == '%') {
            /* Skip format specifiers */
            continue;
        }
        output[j++] = input[i];
    }
    output[j] = '\0';
}

int main(int argc, char *argv[]) {
    const char *input = "Normal message";
    
    if (argc > 1) {
        input = argv[1];
    }
    
    /* SAFE: User input treated as data, not format string */
    log_message_safe(input);
    report_error_safe(input);
    
    return 0;
}