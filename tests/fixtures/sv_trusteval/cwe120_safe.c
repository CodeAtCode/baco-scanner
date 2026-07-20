/*
 * SV-TrustEval-C Fixture: CWE-120 Buffer Copy without Bounds Checking (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: Uses strncpy with explicit bounds checking and null termination
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 32

/* Safe: strncpy with bounds checking */
void process_input_safe(const char *input) {
    char buffer[BUFFER_SIZE];
    size_t input_len = strlen(input);
    
    /* SAFE: Check bounds before copy */
    if (input_len >= BUFFER_SIZE) {
        fprintf(stderr, "Input too long, truncating\n");
        input_len = BUFFER_SIZE - 1;
    }
    
    /* SAFE: strncpy with explicit size, ensure null termination */
    strncpy(buffer, input, input_len);
    buffer[input_len] = '\0';
    
    printf("Processed: %s\n", buffer);
}

/* Safe: fgets with proper size handling */
void read_input_safe(void) {
    char buffer[BUFFER_SIZE];
    
    printf("Enter data: ");
    
    /* SAFE: fgets with explicit buffer size */
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        /* Remove trailing newline if present */
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
        
        /* SAFE: Use snprintf for safe copy */
        char dest[BUFFER_SIZE];
        snprintf(dest, sizeof(dest), "%s", buffer);
        
        printf("Got: %s\n", dest);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        read_input_safe();
        return 0;
    }
    
    process_input_safe(argv[1]);
    return 0;
}