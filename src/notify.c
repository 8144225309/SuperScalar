#include "superscalar/notify.h"
#include "superscalar/lsp_queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

/* --- Log backend --- */

static void notify_log_callback(void *backend_data,
                                uint32_t client_idx,
                                int event_type,
                                int urgency,
                                const char *detail_json) {
    (void)backend_data;
    const char *urgency_str = "normal";
    switch (urgency) {
        case QUEUE_URGENCY_LOW:      urgency_str = "low"; break;
        case QUEUE_URGENCY_NORMAL:   urgency_str = "normal"; break;
        case QUEUE_URGENCY_HIGH:     urgency_str = "high"; break;
        case QUEUE_URGENCY_CRITICAL: urgency_str = "critical"; break;
    }
    printf("[notify] client=%u event=%s urgency=%s",
           client_idx, notify_event_name(event_type), urgency_str);
    if (detail_json)
        printf(" detail=%s", detail_json);
    printf("\n");
    fflush(stdout);
}

/* --- Webhook backend --- */

typedef struct {
    char url[512];
} webhook_data_t;

static void notify_webhook_callback(void *backend_data,
                                    uint32_t client_idx,
                                    int event_type,
                                    int urgency,
                                    const char *detail_json) {
    webhook_data_t *wd = (webhook_data_t *)backend_data;
    if (!wd) return;

    /* Build JSON payload */
    char body[2048];
    snprintf(body, sizeof(body),
             "{\"client_idx\":%u,\"event\":\"%s\",\"urgency\":%d%s%s}",
             client_idx, notify_event_name(event_type), urgency,
             detail_json ? ",\"detail\":" : "",
             detail_json ? detail_json : "");

    /* Fork curl directly — no shell, no injection risk.
       Fire-and-forget: parent doesn't wait. */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: redirect stdout/stderr to /dev/null */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); close(devnull); }
        execlp("curl", "curl", "-s", "-X", "POST",
               "-H", "Content-Type: application/json",
               "-d", body, wd->url, (char *)NULL);
        _exit(127); /* exec failed */
    }
    /* Parent: don't block. Reap with SIGCHLD or let init adopt. */
}

/* --- Exec backend --- */

typedef struct {
    char script[512];
} exec_data_t;

static void notify_exec_callback(void *backend_data,
                                 uint32_t client_idx,
                                 int event_type,
                                 int urgency,
                                 const char *detail_json) {
    exec_data_t *ed = (exec_data_t *)backend_data;
    if (!ed) return;

    char client_str[16], urgency_str[16];
    snprintf(client_str, sizeof(client_str), "%u", client_idx);
    snprintf(urgency_str, sizeof(urgency_str), "%d", urgency);
    const char *event_str = notify_event_name(event_type);
    const char *json_arg = detail_json ? detail_json : "{}";

    /* Fork/exec directly — no shell, no injection risk. */
    pid_t pid = fork();
    if (pid == 0) {
        execlp(ed->script, ed->script, client_str, event_str,
               urgency_str, json_arg, (char *)NULL);
        _exit(127); /* exec failed */
    }
    /* Parent: wait to avoid zombies (exec scripts should be fast). */
    if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
}

/* --- Public API --- */

void notify_init_log(notify_t *n) {
    if (!n) return;
    memset(n, 0, sizeof(*n));
    n->backend_type = NOTIFY_BACKEND_LOG;
    n->callback = notify_log_callback;
    n->backend_data = NULL;
}

void notify_init_webhook(notify_t *n, const char *url) {
    if (!n || !url) return;
    memset(n, 0, sizeof(*n));
    n->backend_type = NOTIFY_BACKEND_WEBHOOK;
    n->callback = notify_webhook_callback;

    webhook_data_t *wd = calloc(1, sizeof(webhook_data_t));
    if (!wd) { n->callback = NULL; return; }
    snprintf(wd->url, sizeof(wd->url), "%s", url);
    n->backend_data = wd;
}

void notify_init_exec(notify_t *n, const char *script_path) {
    if (!n || !script_path) return;
    memset(n, 0, sizeof(*n));
    n->backend_type = NOTIFY_BACKEND_EXEC;
    n->callback = notify_exec_callback;

    exec_data_t *ed = calloc(1, sizeof(exec_data_t));
    if (!ed) { n->callback = NULL; return; }
    snprintf(ed->script, sizeof(ed->script), "%s", script_path);
    n->backend_data = ed;
}

void notify_send(notify_t *n, uint32_t client_idx,
                 int event_type, int urgency,
                 const char *detail_json) {
    if (!n || !n->callback) return;
    n->callback(n->backend_data, client_idx, event_type, urgency, detail_json);
}

void notify_cleanup(notify_t *n) {
    if (!n) return;
    if (n->backend_data) {
        free(n->backend_data);
        n->backend_data = NULL;
    }
    n->callback = NULL;
}

const char *notify_event_name(int event_type) {
    switch (event_type) {
        case NOTIFY_ROTATION_NEEDED:  return "rotation_needed";
        case NOTIFY_EPOCH_RESET:      return "epoch_reset";
        case NOTIFY_FACTORY_EXPIRING: return "factory_expiring";
        case NOTIFY_PAYMENT_RECEIVED: return "payment_received";
        case NOTIFY_QUEUE_ITEM:       return "queue_item";
        default:                      return "unknown";
    }
}
