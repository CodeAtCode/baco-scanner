/* eval/fixtures/c-uaf/innocent.c
 * BACO Eval Fixture: innocent file - allocation freed with no later use
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int store_preference(void) {
    char *scratch = malloc(32);
    if (scratch == NULL) {
        return 1;
    }
    strcpy(scratch, "theme=dark");
    puts(scratch);
    free(scratch);
    return 0;
}
