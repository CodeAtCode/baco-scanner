// Vulnerable C++ code for testing
#include <cstdio>
#include <cstdlib>
#include <cstring>

void gets_vulnerable() {
    char buffer[100];
    gets(buffer);  // VULNERABLE: gets() is always unsafe
}

void strcpy_vulnerable() {
    char dest[50];
    const char* src = "user input";
    strcpy(dest, src);  // VULNERABLE: no bounds checking
}

void memcpy_vulnerable() {
    char dest[50];
    const char* src = "user input";
    size_t n = atoi("100");  // Variable size from user
    memcpy(dest, src, n);  // VULNERABLE: variable size can overflow
}

void system_vulnerable() {
    char cmd[256];
    scanf("%s", cmd);
    system(cmd);  // VULNERABLE: command injection
}

void printf_vulnerable() {
    char fmt[100];
    scanf("%s", fmt);
    printf(fmt);  // VULNERABLE: format string vulnerability
}
