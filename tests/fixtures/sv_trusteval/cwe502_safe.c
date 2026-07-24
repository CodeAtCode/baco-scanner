/*
 * SV-TrustEval-C Fixture: CWE-502 Deserialization of Untrusted Data (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: Validate input and use safe deserialization pattern
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DATA_SIZE 1024
#define MAX_ALLOWED_SIZE 256

typedef struct {
    int type;
    int size;
    char data[MAX_DATA_SIZE];
} Payload;

/* Helper: Validate payload structure */
static int is_valid_payload(const Payload *payload) {
    if (payload == NULL) {
        return 0;
    }
    
    /* SAFE: Validate size before processing */
    if (payload->size <= 0 || payload->size > MAX_ALLOWED_SIZE) {
        fprintf(stderr, "Invalid payload size: %d\n", payload->size);
        return 0;
    }
    
    /* Validate type */
    if (payload->type != 1 && payload->type != 2) {
        fprintf(stderr, "Unknown payload type: %d\n", payload->type);
        return 0;
    }
    
    return 1;
}

/* Safe: Validate before deserialization */
int process_payload_safe(const char *input, size_t input_len) {
    Payload *payload;
    
    /* SAFE: Validate input size before deserialization */
    if (input_len == 0 || input_len > MAX_DATA_SIZE) {
        fprintf(stderr, "Input size out of bounds: %zu\n", input_len);
        return -1;
    }
    
    payload = (Payload *)malloc(sizeof(Payload));
    if (payload == NULL) {
        return -1;
    }
    
    /* Initialize to zero */
    memset(payload, 0, sizeof(Payload));
    
    /* SAFE: Bounds-checked copy */
    memcpy(payload->data, input, input_len);
    payload->size = (int)input_len;
    payload->type = 1;
    
    /* SAFE: Validate before processing */
    if (!is_valid_payload(payload)) {
        free(payload);
        return -1;
    }
    
    printf("Processing validated payload of size %d\n", payload->size);
    
    free(payload);
    return 0;
}

int main(int argc, char *argv[]) {
    const char *safe_input = "safe serialized data";
    
    if (argc > 1) {
        safe_input = argv[1];
    }
    
    /* SAFE: Validate and process input */
    process_payload_safe(safe_input, strlen(safe_input));
    
    return 0;
}