/*
 * SV-TrustEval-C Fixture: CWE-676 Use of Potentially Dangerous Function (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: Using gets() which has no bounds checking
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 64

/* Vulnerable: Using gets() - deprecated and dangerous */
void read_input_vulnerable(void) {
    char buffer[BUFFER_SIZE];
    
    printf("Enter your name: ");
    
    /* VULNERABLE: gets() has no bounds checking - buffer overflow! */
    /* gets() was removed from C11 standard for this reason */
    gets(buffer);
    
    printf("Hello, %s!\n", buffer);
}

/* Vulnerable: Using strcpy without bounds check */
void copy_data_vulnerable(const char *source) {
    char dest[BUFFER_SIZE];
    
    /* VULNERABLE: strcpy has no bounds checking */
    strcpy(dest, source);  /* Buffer overflow if source > BUFFER_SIZE */
    
    printf("Copied: %s\n", dest);
}

/* Vulnerable: Using strcat without bounds check */
void concat_data_vulnerable(const char *suffix) {
    char buffer[BUFFER_SIZE] = "Hello, ";
    
    /* VULNERABLE: strcat has no bounds checking */
    strcat(buffer, suffix);  /* Buffer overflow if result > BUFFER_SIZE */
    
    printf("Result: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    const char *test_input = "World";
    
    if (argc > 1) {
        test_input = argv[1];
    }
    
    read_input_vulnerable();
    copy_data_vulnerable(test_input);
    concat_data_vulnerable(test_input);
    
    return 0;
}