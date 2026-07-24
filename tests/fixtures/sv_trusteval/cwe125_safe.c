/*
 * SV-TrustEval-C Fixture: CWE-125 Out-of-bounds Read (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: Bounds checking before array access
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 64
#define ARRAY_SIZE 10

/* Safe: Validate offset before access */
char *read_data_safe(const char *input, int offset) {
    char *buffer;
    char *result;
    
    buffer = (char *)malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        return NULL;
    }
    
    strncpy(buffer, input, BUFFER_SIZE - 1);
    buffer[BUFFER_SIZE - 1] = '\0';
    
    /* SAFE: Bounds check before access */
    if (offset < 0 || offset >= (int)strlen(buffer)) {
        fprintf(stderr, "Offset %d out of bounds (max %zu)\n", 
                offset, strlen(buffer) - 1);
        free(buffer);
        return NULL;
    }
    
    result = &buffer[offset];
    printf("Reading from offset %d: %s\n", offset, result);
    
    /* SAFE: Return copy, not pointer to freed memory */
    char *copy = strdup(result);
    free(buffer);
    return copy;
}

/* Safe: Proper bounds check */
int process_array_safe(int *arr, int index) {
    int values[ARRAY_SIZE] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    
    /* SAFE: Correct bounds check using < not <= */
    if (index < 0 || index >= ARRAY_SIZE) {
        fprintf(stderr, "Index %d out of bounds (0-%d)\n", index, ARRAY_SIZE - 1);
        return -1;
    }
    
    return values[index];
}

int main(int argc, char *argv[]) {
    int offset = 10;
    int index = 5;
    
    if (argc > 1) {
        offset = atoi(argv[1]);
    }
    if (argc > 2) {
        index = atoi(argv[2]);
    }
    
    char *result = read_data_safe("test data string", offset);
    if (result != NULL) {
        printf("Result: %s\n", result);
        free(result);
    }
    printf("Array value: %d\n", process_array_safe(NULL, index));
    
    return 0;
}