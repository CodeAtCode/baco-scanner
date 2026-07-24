/*
 * SV-TrustEval-C Fixture: CWE-400 Uncontrolled Resource Consumption (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: Enforce resource limits
 */

#include <stdio.h>
#include <stdlib.h>

#define MAX_RECURSION_DEPTH 1000
#define MAX_ALLOCATION_SIZE (1024 * 1024)  /* 1MB limit */

/* Safe: Enforce recursion depth limit */
int recursive_process_safe(int depth) {
    char buffer[256];
    
    /* SAFE: Check against maximum allowed depth */
    if (depth > MAX_RECURSION_DEPTH) {
        fprintf(stderr, "Recursion depth %d exceeds maximum %d\n", 
                depth, MAX_RECURSION_DEPTH);
        return 1;
    }
    
    printf("Depth: %d\n", depth);
    
    if (depth > 0) {
        snprintf(buffer, sizeof(buffer), "Processing at depth %d", depth);
        return recursive_process_safe(depth - 1);
    }
    
    return 0;
}

/* Safe: Enforce allocation size limit */
char *allocate_unbounded_safe(int size) {
    /* SAFE: Enforce upper bound on allocation */
    if (size <= 0 || size > MAX_ALLOCATION_SIZE) {
        fprintf(stderr, "Allocation size %d out of bounds (max %d)\n",
                size, MAX_ALLOCATION_SIZE);
        return NULL;
    }
    
    char *buffer = (char *)malloc(size);
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    return buffer;
}

int main(int argc, char *argv[]) {
    int depth = 100;
    
    if (argc > 1) {
        depth = atoi(argv[1]);
    }
    
    printf("Starting recursive process with depth %d (max %d)\n", 
           depth, MAX_RECURSION_DEPTH);
    recursive_process_safe(depth);
    
    return 0;
}