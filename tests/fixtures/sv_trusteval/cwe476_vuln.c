/*
 * SV-TrustEval-C Fixture: CWE-476 NULL Pointer Dereference (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: Dereferencing pointer without NULL check
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 64

/* Vulnerable: No NULL check after malloc */
char *process_input_vulnerable(const char *input) {
    char *buffer;
    char *result;
    
    /* VULNERABLE: malloc can return NULL */
    buffer = (char *)malloc(BUFFER_SIZE);
    
    /* VULNERABLE: No NULL check - dereference if allocation failed */
    strcpy(buffer, input);
    
    result = (char *)malloc(BUFFER_SIZE);
    /* VULNERABLE: No NULL check */
    strcpy(result, buffer);
    
    free(buffer);
    return result;
}

/* Vulnerable: NULL check in wrong order */
int process_struct_vulnerable(int *value) {
    /* VULNERABLE: Dereference before NULL check */
    int result = *value;  /* Crash if value is NULL */
    
    /* This check comes too late */
    if (value == NULL) {
        return -1;
    }
    
    return result * 2;
}

int main(int argc, char *argv[]) {
    const char *input = "test";
    int *null_ptr = NULL;
    int value = 42;
    
    if (argc > 1) {
        input = argv[1];
    }
    
    char *result = process_input_vulnerable(input);
    if (result != NULL) {
        printf("Result: %s\n", result);
        free(result);
    }
    
    printf("Struct value: %d\n", process_struct_vulnerable(&value));
    printf("NULL struct value: %d\n", process_struct_vulnerable(null_ptr));
    
    return 0;
}