// ARTIFICIAL STATIC FIXTURE - DO NOT EXECUTE or compile.
// Global C-library forms intentionally exercise both C and C++ grammars.
#include <stdio.h>
#include <stdlib.h>

void vulnerable_environment_cpp() {
    const char *supplied = getenv("LOCALGUARD_FIXTURE_COMMAND");
    const char *forwarded = supplied;
    // ruleid: localguard.security.c-environment-shell
    popen(forwarded, "r");
}

void clean_environment_cpp() {
    const char *supplied = getenv("LOCALGUARD_FIXTURE_LABEL");
    // ok: localguard.security.c-environment-shell
    puts(supplied);
    // ok: localguard.security.c-environment-shell
    system("fixture-tool --version");
}

void vulnerable_input_cpp() {
    char buffer[32];
    // ruleid: localguard.security.c-unbounded-gets
    gets(buffer);
}

void clean_input_cpp() {
    char buffer[32];
    // ok: localguard.security.c-unbounded-gets
    fgets(buffer, sizeof(buffer), stdin);
}
