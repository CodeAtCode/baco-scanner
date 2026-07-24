/*
 * SV-TrustEval-C Fixture: CWE-190 Integer Overflow (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: Overflow check before arithmetic operation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define MAX_ITEMS 1000
#define ITEM_SIZE 64

/* Safe: Check for overflow before multiplication */
char *allocate_buffer_safe(unsigned int count) {
    size_t total_size;
    char *buffer;
    
    /* SAFE: Check for potential overflow */
    if (count > SIZE_MAX / ITEM_SIZE) {
        fprintf(stderr, "Count too large - would overflow\n");
        return NULL;
    }
    
    /* Additional bounds check */
    if (count > MAX_ITEMS) {
        fprintf(stderr, "Count exceeds maximum allowed\n");
        return NULL;
    }
    
    total_size = count * ITEM_SIZE;
    buffer = (char *)malloc(total_size);
    
    if (buffer == NULL) {
        return NULL;
    }
    
    for (unsigned int i = 0; i < count; i++) {
        memset(buffer + (i * ITEM_SIZE), 0, ITEM_SIZE);
    }
    
    return buffer;
}

int main(int argc, char *argv[]) {
    unsigned int count = MAX_ITEMS;
    
    if (argc > 1) {
        count = (unsigned int)atoi(argv[1]);
    }
    
    char *buf = allocate_buffer_safe(count);
    if (buf != NULL) {
        printf("Allocated buffer safely\n");
        free(buf);
    }
    
    return 0;
}