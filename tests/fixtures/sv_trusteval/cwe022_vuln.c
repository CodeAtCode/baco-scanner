/*
 * SV-TrustEval-C Fixture: CWE-22 Path Traversal (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: User input concatenated to file path without validation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE_DIR "/var/data"
#define MAX_PATH 256

/* Vulnerable: Direct concatenation without path validation */
int read_file_vulnerable(const char *filename) {
    char filepath[MAX_PATH];
    FILE *fp;
    
    /* VULNERABLE: No validation - allows ../../../etc/passwd */
    snprintf(filepath, sizeof(filepath), "%s/%s", BASE_DIR, filename);
    
    printf("Opening: %s\n", filepath);
    
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }
    
    /* Read and display file contents */
    int c;
    while ((c = fgetc(fp)) != EOF) {
        putchar(c);
    }
    
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    
    return read_file_vulnerable(argv[1]);
}