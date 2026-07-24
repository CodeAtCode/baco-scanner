/*
 * SV-TrustEval-C Fixture: CWE-476 NULL Pointer Dereference (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: Check for NULL before dereferencing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 64

/* Safe: Validate after allocation */
char *process_input_safe(const char *input) {
    char *buffer;
    char *result;
    
    buffer = (char *)malloc(BUFFER_SIZE);
    /* SAFE: Check for allocation failure */
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    
    strcpy(buffer, input);
    
    result = (char *)malloc(BUFFER_SIZE);
    /* SAFE: Check for allocation failure */
    if (result == NULL) {
        free(buffer);
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    
    strcpy(result, buffer);
    free(buffer);
    return result;
}

/* Safe: NULL check before dereference */
int process_struct_safe(int *value) {
    /* SAFE: Check for NULL before dereferencing */
    if (value == NULL) {
        fprintf(stderr, "NULL pointer passed to process_struct\n");
        return -1;
    }
    
    /* Now safe to dereference */
    return *value * 2;
}

int main(int argc, char *argv[]) {
    const char *input = "test";
    int *null_ptr = NULL;
    int value = 42;
    
    if (argc > 1) {
        input = argv[1];
    }
    
    char *result = process_input_safe(input);
    if (result != NULL) {
        printf("Result: %s\n", result);
        free(result);
    }
    
    printf("Struct value: %d\n", process_struct_safe(&value));
    printf("NULL struct value: %d\n", process_struct_safe(null_ptr));
    
    return 0;
}