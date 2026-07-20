/*
 * SV-TrustEval-C Fixture: CWE-22 Path Traversal (Safe/Patched Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Fix: Validates path doesn't contain '..' and resolves to expected base
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE_DIR "/var/data"
#define MAX_PATH 256

/* Helper: Check for path traversal attempts */
int is_safe_path(const char *filename) {
    /* Check for .. sequence */
    if (strstr(filename, "..") != NULL) {
        return 0;  /* Unsafe - contains .. */
    }
    
    /* Check for absolute path */
    if (filename[0] == '/') {
        return 0;  /* Unsafe - absolute path */
    }
    
    /* Check for null bytes (path truncation attack) */
    for (size_t i = 0; filename[i]; i++) {
        if (filename[i] == '\0') {
            return 0;
        }
    }
    
    return 1;  /* Safe */
}

/* Safe: Path validation before concatenation */
int read_file_safe(const char *filename) {
    char filepath[MAX_PATH];
    char realpath_result[MAX_PATH];
    FILE *fp;
    
    /* SAFE: Validate path before use */
    if (!is_safe_path(filename)) {
        fprintf(stderr, "Error: Invalid path - traversal attempt detected\n");
        return -1;
    }
    
    snprintf(filepath, sizeof(filepath), "%s/%s", BASE_DIR, filename);
    
    /* Optional: resolve and verify real path is under base dir */
    if (realpath(filepath, realpath_result) == NULL) {
        perror("realpath");
        return -1;
    }
    
    /* Verify resolved path starts with BASE_DIR */
    if (strncmp(realpath_result, BASE_DIR, strlen(BASE_DIR)) != 0) {
        fprintf(stderr, "Error: Path escapes base directory\n");
        return -1;
    }
    
    printf("Opening: %s\n", realpath_result);
    
    fp = fopen(realpath_result, "r");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }
    
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
    
    return read_file_safe(argv[1]);
}