/* eval/fixtures/c-overflow/safe_twin.c
 * BACO Eval Fixture: Secure buffer handling (bounded copy)
 * This is the SECURE version - any finding here is a false positive
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE 64

/* SECURE: Copies data with bounds checking */
void copy_user_data(char *dest, const char *src, size_t len) {
    /*
     * SECURE: Bounds-check before copying.
     * Use the minimum of requested length and available buffer space.
     */
    size_t safe_len = (len < BUFFER_SIZE) ? len : BUFFER_SIZE - 1;
    memcpy(dest, src, safe_len);
    dest[safe_len] = '\0';  // Null-terminate
}

/* Process incoming network data */
int process_packet(const char *data, size_t data_len) {
    char buffer[BUFFER_SIZE];
    
    /* Bounds-checked copy */
    copy_user_data(buffer, data, data_len);
    
    printf("Processed %zu bytes (truncated if needed)\n", data_len);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <data>\n", argv[0]);
        return 1;
    }
    
    size_t len = strlen(argv[1]);
    process_packet(argv[1], len);
    
    return 0;
}