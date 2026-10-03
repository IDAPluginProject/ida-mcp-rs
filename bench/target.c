/*
 * Benchmark target. Small enough to analyze in seconds, structured enough
 * that the tasks in bench/run.py have unambiguous answers:
 *   - exactly three functions reference the "license expired" string
 *   - helper_mix is a leaf whose purpose is readable from its body
 * Built by the harness as a thin arm64 Mach-O and a universal arm64+x86_64
 * Mach-O with DWARF, so symbol names survive into the database.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *EXPIRED = "license expired";
#ifndef BANNER_TEXT
#define BANNER_TEXT "bench target v2"
#endif
static const char *BANNER = BANNER_TEXT;

static unsigned helper_mix(unsigned value) {
    return ((value * 2654435761u) >> 7) ^ 0x5a5a;
}

static unsigned checksum_name(const char *name) {
    unsigned sum = 0;
    for (; *name; ++name) {
        sum = helper_mix(sum + (unsigned char)*name);
    }
    return sum;
}

int validate_license(const char *name, long expiry) {
    if (expiry < time(NULL)) {
        fputs(EXPIRED, stderr);
        return -1;
    }
    return checksum_name(name) % 97 == 0 ? 0 : 1;
}

void report_status(int code) {
    if (code < 0) {
        printf("status: %s\n", EXPIRED);
    } else {
        printf("status: %d\n", code);
    }
}

static void audit_log(const char *event) {
    if (strcmp(event, EXPIRED) == 0) {
        fprintf(stderr, "audit: %s\n", EXPIRED);
    } else {
        fprintf(stderr, "audit: %s\n", event);
    }
}

void print_banner(void) {
    puts(BANNER);
}

int main(int argc, char **argv) {
    print_banner();
    const char *name = argc > 1 ? argv[1] : "anonymous";
    long expiry = argc > 2 ? strtol(argv[2], NULL, 10) : 0;
    int code = validate_license(name, expiry);
    report_status(code);
    audit_log(code < 0 ? EXPIRED : "ok");
    return code;
}
