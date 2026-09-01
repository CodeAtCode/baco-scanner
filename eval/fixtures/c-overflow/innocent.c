/* eval/fixtures/c-overflow/innocent.c
 * BACO Eval Fixture: Innocent file with no vulnerabilities
 */

#include <stdio.h>
#include <string.h>

/* Safe string length calculation */
size_t safe_strlen(const char *str) {
    if (str == NULL) {
        return 0;
    }
    return strlen(str);
}

/* Safe string copy with bounds checking */
int safe_copy(char *dest, size_t dest_size, const char *src) {
    if (dest == NULL || src == NULL || dest_size == 0) {
        return -1;
    }
    
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dest_size - 1) ? src_len : dest_size - 1;
    
    memcpy(dest, src, copy_len);
    dest[copy_len] = '\0';
    
    return 0;
}