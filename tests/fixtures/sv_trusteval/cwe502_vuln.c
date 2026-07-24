/*
 * SV-TrustEval-C Fixture: CWE-502 Deserialization of Untrusted Data (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: Deserializing untrusted data without validation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DATA_SIZE 1024

typedef struct {
    int type;
    int size;
    char data[MAX_DATA_SIZE];
} Payload;

/* Vulnerable: Direct deserialization without validation */
int process_payload_vulnerable(const char *input, size_t input_len) {
    Payload *payload;
    
    /* VULNERABLE: No validation of input before deserialization */
    /* In real code: this could be pickle/yaml/json deserialization */
    
    payload = (Payload *)malloc(sizeof(Payload));
    if (payload == NULL) {
        return -1;
    }
    
    /* VULNERABLE: Copy without bounds checking */
    memcpy(payload->data, input, input_len);
    payload->size = (int)input_len;
    payload->type = 1;
    
    /* VULNERABLE: Process deserialized data without validation */
    printf("Processing payload of size %d\n", payload->size);
    
    /* In real code: execute deserialized object methods */
    /* This could lead to arbitrary code execution */
    
    free(payload);
    return 0;
}

int main(int argc, char *argv[]) {
    const char *malicious_input = "malicious serialized data";
    
    if (argc > 1) {
        malicious_input = argv[1];
    }
    
    /* VULNERABLE: Process untrusted input */
    process_payload_vulnerable(malicious_input, strlen(malicious_input));
    
    return 0;
}