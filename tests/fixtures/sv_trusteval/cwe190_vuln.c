/*
 * SV-TrustEval-C Fixture: CWE-190 Integer Overflow (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: Unchecked arithmetic leading to buffer overflow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ITEMS 1000
#define ITEM_SIZE 64

/* Vulnerable: No overflow check before allocation */
char *allocate_buffer_vulnerable(unsigned int count) {
    size_t total_size;
    char *buffer;
    
    /* VULNERABLE: Multiplication can overflow */
    total_size = count * ITEM_SIZE;
    
    /* Overflow wraps around, allocating small buffer */
    buffer = (char *)malloc(total_size);
    if (buffer == NULL) {
        return NULL;
    }
    
    /* Buffer overflow when count is large */
    for (unsigned int i = 0; i < count; i++) {
        /* This will overflow if total_size wrapped */
        memset(buffer + (i * ITEM_SIZE), 0, ITEM_SIZE);
    }
    
    return buffer;
}

int main(int argc, char *argv[]) {
    unsigned int count = MAX_ITEMS;
    
    if (argc > 1) {
        count = (unsigned int)atoi(argv[1]);
    }
    
    char *buf = allocate_buffer_vulnerable(count);
    if (buf != NULL) {
        printf("Allocated buffer\n");
        free(buf);
    }
    
    return 0;
}