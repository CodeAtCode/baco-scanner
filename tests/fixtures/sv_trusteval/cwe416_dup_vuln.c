/*
 * SV-TrustEval-C Fixture: CWE-416 Use After Free (Vulnerable Variant - Alternative)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: Dangling pointer in callback scenario
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 128

typedef struct {
    char *data;
    void (*callback)(char *);
} Context;

/* Vulnerable: Callback uses freed memory */
void process_with_callback_vulnerable(Context *ctx) {
    char *local_buffer;
    
    local_buffer = (char *)malloc(BUFFER_SIZE);
    if (local_buffer == NULL) {
        return;
    }
    
    strcpy(local_buffer, "sensitive data");
    ctx->data = local_buffer;
    
    /* Process data */
    printf("Processing: %s\n", ctx->data);
    
    /* Free the data */
    free(ctx->data);
    ctx->data = NULL;
    
    /* VULNERABLE: Callback receives freed pointer context */
    if (ctx->callback != NULL) {
        /* Bug: callback expects valid data but it's freed */
        ctx->callback(local_buffer);  /* local_buffer is now freed! */
    }
}

void dummy_callback(char *data) {
    /* VULNERABLE: Accessing freed memory */
    if (data != NULL) {
        printf("Callback sees: %s\n", data);  /* Use after free! */
    }
}

int main(int argc, char *argv[]) {
    Context ctx = {0};
    ctx.callback = dummy_callback;
    
    process_with_callback_vulnerable(&ctx);
    
    return 0;
}