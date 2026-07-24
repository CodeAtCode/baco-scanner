/*
 * SV-TrustEval-C Fixture: CWE-676 Use of Potentially Dangerous Function (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: Use safe alternatives with bounds checking
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 64

/* Safe: Use fgets() with explicit size limit */
void read_input_safe(void) {
    char buffer[BUFFER_SIZE];
    
    printf("Enter your name: ");
    
    /* SAFE: fgets() with size limit - prevents buffer overflow */
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        /* Remove trailing newline if present */
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
        printf("Hello, %s!\n", buffer);
    }
}

/* Safe: Use strncpy with explicit bounds */
void copy_data_safe(const char *source) {
    char dest[BUFFER_SIZE];
    
    /* SAFE: strncpy with size limit */
    strncpy(dest, source, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0';  /* Ensure null termination */
    
    printf("Copied: %s\n", dest);
}

/* Safe: Use strncat with explicit bounds */
void concat_data_safe(const char *suffix) {
    char buffer[BUFFER_SIZE] = "Hello, ";
    
    /* SAFE: strncat with size limit */
    size_t remaining = sizeof(buffer) - strlen(buffer) - 1;
    strncat(buffer, suffix, remaining);
    
    printf("Result: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    const char *test_input = "World";
    
    if (argc > 1) {
        test_input = argv[1];
    }
    
    read_input_safe();
    copy_data_safe(test_input);
    concat_data_safe(test_input);
    
    return 0;
}