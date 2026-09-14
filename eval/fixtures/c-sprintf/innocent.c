/* eval/fixtures/c-sprintf/innocent.c
 * BACO Eval Fixture: innocent file - fixed string, no external input
 */

#include <stdio.h>

void print_banner(void) {
    const char *banner = "BACO Demo Server";
    puts(banner);
}
