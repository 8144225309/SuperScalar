#include "superscalar/log.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

static int g_json_enabled = 0;

void ss_log_set_json(int enabled) { g_json_enabled = enabled; }
int  ss_log_json_enabled(void)    { return g_json_enabled; }

void ss_log_event(const char *level, const char *event, ...)
{
    if (!g_json_enabled) return;

    time_t now = time(NULL);
    fprintf(stderr, "{\"ts\":%ld,\"level\":\"%s\",\"event\":\"%s\"",
            (long)now, level ? level : "info", event ? event : "unknown");

    va_list ap;
    va_start(ap, event);
    for (;;) {
        const char *key = va_arg(ap, const char *);
        if (!key) break;
        const char *val = va_arg(ap, const char *);
        if (!val) { /* last key without value */ break; }
        fprintf(stderr, ",\"%s\":\"%s\"", key, val);
    }
    va_end(ap);

    fprintf(stderr, "}\n");
}
