/* eval/fixtures/c-sprintf/vulnerable.c
 * BACO Eval Fixture: Buffer overflow via unbounded sprintf (CWE-787)
 * The vulnerability is on line 19 - sprintf into fixed 64-byte buffer
 */

#include <stdio.h>

#define GREETING_MAX 64

/* VULNERABLE: copies the attacker-controlled name into a fixed buffer
 * without any length limit. Names longer than 63 bytes write past
 * the end of the buffer.
 */
void build_greeting(char *out, const char *name) {
    /*
     * VULNERABILITY: sprintf performs an unbounded copy into `out`,
     * which callers allocate as char[GREETING_MAX].
     */
    sprintf(out, "Hello, %s!", name);
}

int handle_request(const char *user_name) {
    char greeting[GREETING_MAX];
    build_greeting(greeting, user_name);
    puts(greeting);
    return 0;
}
