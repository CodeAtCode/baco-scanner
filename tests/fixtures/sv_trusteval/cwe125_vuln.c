/*
 * SV-TrustEval-C Fixture: CWE-125 Out-of-bounds Read (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: Reading beyond allocated buffer bounds
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 64

/* Vulnerable: Read beyond buffer bounds */
char *read_data_vulnerable(const char *input, int offset) {
    char *buffer;
    char *result;
    
    buffer = (char *)malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        return NULL;
    }
    
    strncpy(buffer, input, BUFFER_SIZE - 1);
    buffer[BUFFER_SIZE - 1] = '\0';
    
    /* VULNERABLE: No bounds check on offset */
    /* Reading beyond buffer if offset is large */
    result = &buffer[offset];
    
    printf("Reading from offset %d: %s\n", offset, result);
    
    /* In some cases, this reads beyond allocated memory */
    free(buffer);
    return result;  /* Returns pointer to freed memory too! */
}

/* Vulnerable: Off-by-one read */
int process_array_vulnerable(int *arr, int index) {
    int values[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    
    /* VULNERABLE: No bounds check - index could be >= 10 */
    /* Off-by-one error: should be index < 10, not index <= 10 */
    if (index <= 10) {
        return values[index];  /* Reads beyond array when index == 10 */
    }
    
    return -1;
}

int main(int argc, char *argv[]) {
    int offset = 60;
    int index = 10;
    
    if (argc > 1) {
        offset = atoi(argv[1]);
    }
    if (argc > 2) {
        index = atoi(argv[2]);
    }
    
    read_data_vulnerable("test data string", offset);
    printf("Array value: %d\n", process_array_vulnerable(NULL, index));
    
    return 0;
}