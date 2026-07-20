/*
 * SV-TrustEval-C Fixture: CWE-416 Use After Free (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: Pointer used after memory is freed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 64

/* Vulnerable: Data used after free */
char *process_data_vulnerable(const char *input) {
    char *buffer = (char *)malloc(BUFFER_SIZE);
    char *result = NULL;
    
    if (buffer == NULL) {
        return NULL;
    }
    
    strncpy(buffer, input, BUFFER_SIZE - 1);
    buffer[BUFFER_SIZE - 1] = '\0';
    
    printf("Processing: %s\n", buffer);
    
    /* Free the buffer */
    free(buffer);
    
    /* VULNERABLE: Use after free - accessing freed memory */
    /* In some cases this might appear to work, but it's undefined behavior */
    if (strlen(buffer) > 0) {
        result = buffer;  /* Returning dangling pointer! */
    }
    
    return result;
}

/* Vulnerable: Double-free scenario */
void cleanup_vulnerable(char *ptr) {
    if (ptr != NULL) {
        free(ptr);
        /* VULNERABLE: No nullification - pointer still valid */
        /* If this function is called again, double-free occurs */
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <data>\n", argv[0]);
        return 1;
    }
    
    char *result = process_data_vulnerable(argv[1]);
    if (result != NULL) {
        /* Using the dangling pointer - undefined behavior */
        printf("Result: %s\n", result);
    }
    
    return 0;
}