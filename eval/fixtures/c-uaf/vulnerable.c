/* eval/fixtures/c-uaf/vulnerable.c
 * BACO Eval Fixture: Use-after-free via dangling pointer (CWE-416)
 * The vulnerability is on line 27 - read through pointer freed at line 25
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *make_session_token(void) {
    char *token = malloc(32);
    if (token == NULL) {
        return NULL;
    }
    strcpy(token, "session-token");
    return token;
}

/* VULNERABLE: logs the token after releasing the allocation. */
int revoke_session(void) {
    char *token = make_session_token();
    if (token == NULL) {
        return 1;
    }
    free(token);
    /* token now dangles; the freed heap slot can be reallocated. */
    printf("revoked session: %s\n", token);
    return 0;
}
