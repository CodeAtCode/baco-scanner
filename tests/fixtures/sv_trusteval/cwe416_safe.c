/*
 * SV-TrustEval-C Fixture: CWE-416 Use After Free (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: Set pointer to NULL after free, validate before use
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 64

/* Safe: Proper pointer management after free */
char *process_data_safe(const char *input) {
    char *buffer = (char *)malloc(BUFFER_SIZE);
    char *result = NULL;
    
    if (buffer == NULL) {
        return NULL;
    }
    
    strncpy(buffer, input, BUFFER_SIZE - 1);
    buffer[BUFFER_SIZE - 1] = '\0';
    
    printf("Processing: %s\n", buffer);
    
    /* Create a copy before freeing */
    if (strlen(buffer) > 0) {
        result = strdup(buffer);  /* Safe: new allocation */
    }
    
    /* SAFE: Free and nullify immediately */
    free(buffer);
    buffer = NULL;
    
    return result;  /* Returns valid copy, not dangling pointer */
}

/* Safe: Proper cleanup with nullification */
void cleanup_safe(char **ptr) {
    if (ptr != NULL && *ptr != NULL) {
        free(*ptr);
        /* SAFE: Nullify the pointer through double pointer */
        *ptr = NULL;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <data>\n", argv[0]);
        return 1;
    }
    
    char *result = process_data_safe(argv[1]);
    if (result != NULL) {
        printf("Result: %s\n", result);
        /* SAFE: Clean up when done */
        free(result);
        result = NULL;
    }
    
    return 0;
}