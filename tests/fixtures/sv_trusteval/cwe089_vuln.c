/*
 * SV-TrustEval-C Fixture: CWE-89 SQL Injection (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: User input directly concatenated into SQL query via sprintf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_USERNAME 64
#define MAX_QUERY 256

/* Vulnerable: Direct string concatenation into SQL query */
int check_user_vulnerable(const char *username) {
    char query[MAX_QUERY];
    char buffer[MAX_USERNAME];
    
    /* No validation - user input goes directly into query */
    snprintf(buffer, sizeof(buffer), "%s", username);
    
    /* VULNERABLE: sprintf with user input in SQL */
    snprintf(query, sizeof(query),
        "SELECT * FROM users WHERE username = '%s'",
        buffer);
    
    printf("Executing: %s\n", query);
    
    /* In real code: mysql_query(conn, query); */
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <username>\n", argv[0]);
        return 1;
    }
    
    return check_user_vulnerable(argv[1]);
}