/* eval/fixtures/c-uaf/safe_twin.c
 * BACO Eval Fixture: Use-after-free safe twin - use before free, no dangling read (CWE-416)
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

/* SECURE: the token is logged while still allocated and the pointer is
 * cleared immediately after free, so no dangling access is possible.
 */
int revoke_session(void) {
    char *token = make_session_token();
    if (token == NULL) {
        return 1;
    }
    printf("revoked session: %s\n", token);
    free(token);
    token = NULL;
    return 0;
}
