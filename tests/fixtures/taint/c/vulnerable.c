// Vulnerable: command injection via user input
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    system(argv[1]);
    return 0;
}
