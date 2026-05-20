#include "superscalar/crash_inject.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void lsp_crash_checkpoint(const char *name) {
    const char *target = getenv("SUPERSCALAR_CRASH_AT");
    if (!target || !name) return;
    if (strcmp(target, name) != 0) return;
    fprintf(stderr,
            "lsp_crash_checkpoint: HIT '%s' — aborting per SUPERSCALAR_CRASH_AT\n",
            name);
    fflush(stderr);
    abort();
}
