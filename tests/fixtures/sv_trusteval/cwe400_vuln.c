/*
 * SV-TrustEval-C Fixture: CWE-400 Uncontrolled Resource Consumption (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: Unbounded recursion leading to stack exhaustion
 */

#include <stdio.h>
#include <stdlib.h>

#define MAX_DEPTH 1000000  /* No actual limit enforced */

/* Vulnerable: No recursion depth limit */
int recursive_process_vulnerable(int depth) {
    char buffer[256];  /* Stack allocation on each call */
    
    printf("Depth: %d\n", depth);
    
    /* VULNERABLE: No base case check - infinite recursion possible */
    /* Even with check, no limit on maximum depth */
    if (depth > 0) {
        snprintf(buffer, sizeof(buffer), "Processing at depth %d", depth);
        /* VULNERABLE: Stack grows unbounded */
        return recursive_process_vulnerable(depth - 1);
    }
    
    return 0;
}

/* Vulnerable: Unbounded memory allocation */
char *allocate_unbounded_vulnerable(int size) {
    /* VULNERABLE: No upper bound on allocation */
    char *buffer = (char *)malloc(size);
    if (buffer == NULL) {
        return NULL;
    }
    return buffer;
}

int main(int argc, char *argv[]) {
    int depth = 1000;
    
    if (argc > 1) {
        depth = atoi(argv[1]);
    }
    
    printf("Starting recursive process with depth %d\n", depth);
    /* VULNERABLE: Can cause stack overflow */
    recursive_process_vulnerable(depth);
    
    return 0;
}