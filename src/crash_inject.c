#include "superscalar/crash_inject.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* SF-CRASH-INJECT-WIRE #245 Half B: runtime crash-checkpoint target.
   Installed via lsp_crash_set_target() (e.g., from the MSG_FORCE_OUT
   dispatcher case).  Empty/uninstalled = "" => no runtime target,
   fall through to the existing SUPERSCALAR_CRASH_AT env-var path.
   THREAD UNSAFE -- single-process test harness only. */
static volatile char g_runtime_target[64] = {0};

void lsp_crash_set_target(const char *name) {
    if (!name || !*name) {
        g_runtime_target[0] = '\0';
        return;
    }
    /* Manual copy with explicit null terminator (strncpy on volatile
       trips -Wcast-qual on some toolchains). */
    size_t i = 0;
    for (; i < 63 && name[i] != '\0'; i++)
        g_runtime_target[i] = name[i];
    g_runtime_target[i] = '\0';
}

void lsp_crash_checkpoint(const char *name) {
    if (!name) return;

    /* Runtime target wins over env var.  Empty runtime target = not
       installed (per lsp_crash_set_target(NULL) semantics). */
    if (g_runtime_target[0] != '\0') {
        /* Compare against a non-volatile snapshot for strcmp safety. */
        char snap[64];
        size_t i = 0;
        for (; i < 63; i++) {
            snap[i] = g_runtime_target[i];
            if (snap[i] == '\0') break;
        }
        snap[63] = '\0';
        if (strcmp(snap, name) == 0) {
            fprintf(stderr,
                    "lsp_crash_checkpoint: HIT '%s' -- aborting (runtime target)\n",
                    name);
            fflush(stderr);
            abort();
        }
    }

    /* Existing env-var path. */
    const char *target = getenv("SUPERSCALAR_CRASH_AT");
    if (!target) return;
    /* Empty env var = always abort (any checkpoint matches). */
    if (*target == '\0' || strcmp(target, name) == 0) {
        fprintf(stderr,
                "lsp_crash_checkpoint: HIT '%s' -- aborting per SUPERSCALAR_CRASH_AT\n",
                name);
        fflush(stderr);
        abort();
    }
}

/* #9 cheat-gate. Default 0 = cheats NOT allowed (fail-safe: a binary that never
   calls superscalar_set_cheat_gate, or runs on any non-regtest network, cannot
   fire a defense-bypass cheat even if the SS_CHEAT_* env var is set). */
static int g_cheat_gate_regtest = 0;

void superscalar_set_cheat_gate(int is_regtest) {
    g_cheat_gate_regtest = is_regtest ? 1 : 0;
}

int superscalar_cheat_allowed(void) {
    return g_cheat_gate_regtest;
}
