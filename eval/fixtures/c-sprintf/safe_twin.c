/* eval/fixtures/c-sprintf/safe_twin.c
 * BACO Eval Fixture: Buffer overflow safe twin - bounded snprintf (CWE-787)
 */

#include <stdio.h>

#define GREETING_MAX 64

/* SECURE: snprintf truncates the output to GREETING_MAX bytes, so the
 * copy can never write past the end of the caller's buffer.
 */
void build_greeting(char *out, const char *name) {
    snprintf(out, GREETING_MAX, "Hello, %s!", name);
}

int handle_request(const char *user_name) {
    char greeting[GREETING_MAX];
    build_greeting(greeting, user_name);
    puts(greeting);
    return 0;
}
