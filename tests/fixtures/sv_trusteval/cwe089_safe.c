/*
 * SV-TrustEval-C Fixture: CWE-89 SQL Injection (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: Uses parameterized query with placeholders
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_USERNAME 64

/* Safe: Parameterized query with placeholder */
int check_user_safe(const char *username) {
    char query[] = "SELECT * FROM users WHERE username = ?";
    const char *param = username;
    
    /* SAFE: Use parameterized query - placeholder for user input */
    printf("Executing parameterized query: %s\n", query);
    printf("With parameter: %s\n", param);
    
    /* In real code:
     * stmt = mysql_prepare(conn, query);
     * mysql_bind_param(stmt, 0, &param);
     * mysql_execute(stmt);
     */
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <username>\n", argv[0]);
        return 1;
    }
    
    return check_user_safe(argv[1]);
}