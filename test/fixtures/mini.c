#include <stdio.h>

static int helper_mix(int value) {
    return (value * 3) ^ 0x5a;
}

int interesting_function(int a, int b) {
    int total = a + b;
    int mixed = helper_mix(total);

    if ((mixed & 1) == 0) {
        return mixed + 7;
    }
    return mixed - 3;
}

int main(int argc, char **argv) {
    int seed = argc > 1 ? (int)argv[1][0] : 1;
    int result = interesting_function(seed, 42);

    printf("result=%d\n", result);
    return result == 0 ? 1 : 0;
}

/* One AArch64 store that Hex-Rays renders as two statements sharing one
 * comment location; stdio_pseudocode_comments.py relies on it. Appended
 * after main so the other functions keep their addresses. */
void clear_pair(long *pair) {
#if defined(__aarch64__)
    __asm__ volatile("stp xzr, xzr, [%0]" : : "r"(pair) : "memory");
#else
    pair[0] = 0;
    pair[1] = 0;
#endif
}
