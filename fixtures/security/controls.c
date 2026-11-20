// ARTIFICIAL STATIC FIXTURE - DO NOT EXECUTE or compile.
// No main, payload, or active endpoint. Legacy gets is parser input only.
#include <stdio.h>
#include <stdlib.h>

void vulnerable_environment(void) {
    const char *supplied = getenv("LOCALGUARD_FIXTURE_COMMAND");
    const char *forwarded = supplied;
    // ruleid: localguard.security.c-environment-shell
    system(forwarded);
}

void clean_environment(void) {
    const char *supplied = getenv("LOCALGUARD_FIXTURE_LABEL");
    // ok: localguard.security.c-environment-shell
    puts(supplied);
    // ok: localguard.security.c-environment-shell
    system("fixture-tool --version");
}

void vulnerable_input(void) {
    char buffer[32];
    // ruleid: localguard.security.c-unbounded-gets
    gets(buffer);
}

void clean_input(void) {
    char buffer[32];
    // ok: localguard.security.c-unbounded-gets
    fgets(buffer, sizeof(buffer), stdin);
    // ok: localguard.security.c-unbounded-gets
    const char *documentation = "gets(buffer)";
    (void)documentation;
}
