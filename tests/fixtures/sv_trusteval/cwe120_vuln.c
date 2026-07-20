/*
 * SV-TrustEval-C Fixture: CWE-120 Buffer Copy without Bounds Checking (Vulnerable Variant)
 * Inspired by SP 2025 arxiv:2505.20630
 * 
 * Vulnerability: strcpy without bounds checking - buffer overflow possible
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 32

/* Vulnerable: strcpy without bounds checking */
void process_input_vulnerable(const char *input) {
    char buffer[BUFFER_SIZE];
    
    /* VULNERABLE: strcpy copies until null terminator - no bounds check */
    strcpy(buffer, input);
    
    printf("Processed: %s\n", buffer);
}

/* Vulnerable: gets is always unsafe */
void read_input_vulnerable(void) {
    char buffer[BUFFER_SIZE];
    
    printf("Enter data: ");
    
    /* VULNERABLE: gets() has no bounds checking - removed from C11 */
    /* Using fgets for demo, but still vulnerable if not sized properly */
    fgets(buffer, sizeof(buffer), stdin);
    
    /* But then we use strcpy elsewhere without checking length */
    char dest[BUFFER_SIZE];
    strcpy(dest, buffer);  /* Still vulnerable if buffer has no null within bounds */
    
    printf("Got: %s\n", dest);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        read_input_vulnerable();
        return 0;
    }
    
    process_input_vulnerable(argv[1]);
    return 0;
}