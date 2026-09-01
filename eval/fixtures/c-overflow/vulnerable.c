/* eval/fixtures/c-overflow/vulnerable.c
 * BACO Eval Fixture: Buffer Overflow via unbounded memcpy (CWE-120/787)
 * The vulnerability is on line 18 - memcpy with attacker-controlled length
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE 64

/* VULNERABLE: Copies data without bounds checking */
void copy_user_data(char *dest, const char *src, size_t len) {
    /*
     * VULNERABILITY: memcpy uses attacker-controlled 'len' without
     * verifying it fits in the destination buffer.
     * This causes a buffer overflow when len > BUFFER_SIZE.
     */
    memcpy(dest, src, len);  // Line 18: off-by-one potential, no bounds check
}

/* Process incoming network data */
int process_packet(const char *data, size_t data_len) {
    char buffer[BUFFER_SIZE];
    
    /* Attacker can send data_len > BUFFER_SIZE */
    copy_user_data(buffer, data, data_len);
    
    printf("Processed %zu bytes\n", data_len);
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