// Safe C++ code for testing
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

void fgets_safe() {
    char buffer[100];
    fgets(buffer, sizeof(buffer), stdin);  // SAFE: bounded input
}

void strncpy_safe() {
    char dest[50];
    const char* src = "safe input";
    strncpy(dest, src, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0';  // SAFE: null-terminated
}

void memcpy_safe() {
    char dest[50];
    const char* src = "safe input";
    // Using std::copy instead of memcpy for safety
    std::copy(src, src + strlen(src), dest);  // SAFE: no raw memcpy
}

void constant_format_safe() {
    const char* msg = "Hello, World!";
    printf("%s", msg);  // SAFE: constant format string
}

void no_system_safe() {
    std::string input = "safe";
    // No system() call - SAFE
}
