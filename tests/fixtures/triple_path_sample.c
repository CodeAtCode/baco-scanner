#include <stdio.h>
void process(int x) {
    int result = 0;
    if (x > 10) {
        result = x * 2;
    } else {
        result = x;
    }
    printf("%d\n", result);
}