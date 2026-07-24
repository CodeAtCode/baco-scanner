/*
 * SV-TrustEval-C Fixture: CWE-416 Use After Free (Safe/Patched Variant - Alternative)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: Copy data before freeing, validate pointers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 128

typedef struct {
    char *data;
    void (*callback)(char *);
} Context;

/* Safe: Copy data before callback, nullify after free */
void process_with_callback_safe(Context *ctx) {
    char *local_buffer;
    char *data_copy;
    
    local_buffer = (char *)malloc(BUFFER_SIZE);
    if (local_buffer == NULL) {
        return;
    }
    
    strcpy(local_buffer, "sensitive data");
    ctx->data = local_buffer;
    
    printf("Processing: %s\n", ctx->data);
    
    /* SAFE: Create copy for callback before freeing */
    data_copy = strdup(local_buffer);
    
    /* Free original */
    free(ctx->data);
    ctx->data = NULL;
    
    /* SAFE: Callback receives independent copy */
    if (ctx->callback != NULL && data_copy != NULL) {
        ctx->callback(data_copy);
        free(data_copy);  /* Clean up the copy */
    }
}

void safe_callback(char *data) {
    /* SAFE: Works with valid copy */
    if (data != NULL) {
        printf("Callback sees: %s\n", data);
    }
}

int main(int argc, char *argv[]) {
    Context ctx = {0};
    ctx.callback = safe_callback;
    
    process_with_callback_safe(&ctx);
    
    return 0;
}