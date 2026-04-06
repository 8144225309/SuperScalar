#ifndef SUPERSCALAR_LOG_H
#define SUPERSCALAR_LOG_H

/* Structured JSON logging for production monitoring.
   When enabled via ss_log_set_json(1), ss_log_event() outputs JSON lines:
   {"ts":1234567890,"level":"info","event":"htlc_add","amount":10000,...}

   When disabled (default), ss_log_event() is a no-op. */

void ss_log_set_json(int enabled);
int  ss_log_json_enabled(void);

/* Log a structured event. Extra fields are key-value pairs terminated by NULL.
   Example: ss_log_event("info", "htlc_add", "amount", "10000", "channel", "0", NULL); */
void ss_log_event(const char *level, const char *event, ...);

#endif /* SUPERSCALAR_LOG_H */
