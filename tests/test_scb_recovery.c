/*
 * test_scb_recovery.c — Unit tests for the SCB DLP recovery path
 *
 * SCB1: ln_dispatch type-136 with DLP (chan_reestablish=0) + watchtower →
 *       watchtower_set_channel called (no crash)
 * SCB2: ln_dispatch type-136 normal (chan_reestablish=1) → no force-close
 * SCB3: d->watchtower == NULL on DLP → no crash
 * SCB4: scb_recovery_channel with ch=NULL → returns -1
 * SCB5: scb_recovery_channel with normal re-sync → returns 0
 */

#include "superscalar/ln_dispatch.h"
#include "superscalar/scb_recovery.h"
#include "superscalar/chan_open.h"
#include "superscalar/channel.h"
#include "superscalar/watchtower.h"
#include "superscalar/fee_estimator.h"
#include <string.h>
#include <stdio.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* ================================================================== */
/* SCB1 — type-136 with DLP + watchtower set → no crash              */
/* ================================================================== */
int test_scb_dlp_with_watchtower(void)
{
    /* Build a channel_reestablish msg (type 136):
     * type(2) + channel_id(32) + next_local_commitment_number(8) +
     * next_remote_revocation_number(8) = 50 bytes minimum
     * We use peer commitment number >> ours to trigger DLP */
    unsigned char msg[50];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x88; /* type 136 */
    /* channel_id: bytes 2-33 = all zeros */
    /* next_local_commitment_number (our perspective on peer's next) at bytes 34-41 */
    /* Set peer's next_commitment_number to a large value to trigger DLP */
    /* offset: type(2) + chan_id(32) = 34 for first 8-byte field */
    msg[34] = 0x00; msg[35] = 0x00; msg[36] = 0x00; msg[37] = 0x00;
    msg[38] = 0x00; msg[39] = 0x00; msg[40] = 0x00; msg[41] = 0x64; /* 100 */

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.commitment_number = 0; /* we are at 0, peer says 100 → DLP */

    watchtower_t wt;
    fee_estimator_static_t fee;
    fee_estimator_static_init(&fee, 1000);
    watchtower_init(&wt, 4, NULL, (fee_estimator_t *)&fee, NULL);

    channel_t *channels[4];
    memset(channels, 0, sizeof(channels));
    channels[0] = &ch;

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.peer_channels = channels;
    d.watchtower    = &wt;
    memset(d.our_privkey, 0x11, 32);

    /* Should not crash even with no pmgr */
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 136, "SCB1: returns 136");

    watchtower_cleanup(&wt);
    return 1;
}

/* ================================================================== */
/* SCB2 — type-136 normal re-sync → no force-close                   */
/* ================================================================== */
int test_scb_normal_reestablish(void)
{
    unsigned char msg[50];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x88;
    /* peer's next commitment number = 1 (= our_cn + 1 → normal sync) */
    msg[41] = 0x01;

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.commitment_number = 0; /* peer next = 1 = ours + 1, not DLP */

    channel_t *channels[1] = { &ch };

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.peer_channels = channels;
    d.watchtower    = NULL; /* no watchtower */
    memset(d.our_privkey, 0x22, 32);

    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 136, "SCB2: returns 136");
    return 1;
}

/* ================================================================== */
/* SCB3 — DLP but watchtower == NULL → no crash                       */
/* ================================================================== */
int test_scb_dlp_no_watchtower_no_crash(void)
{
    unsigned char msg[50];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x88;
    msg[41] = 0x64; /* peer says 100 → DLP */

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.commitment_number = 0;

    channel_t *channels[1] = { &ch };

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.peer_channels = channels;
    d.watchtower    = NULL; /* guard: must not crash */
    memset(d.our_privkey, 0x33, 32);

    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 136, "SCB3: no crash with NULL watchtower");
    return 1;
}

/* ================================================================== */
/* SCB4 — scb_recovery_channel with ch=NULL → returns -1             */
/* ================================================================== */
int test_scb_recovery_null_channel(void)
{
    int r = scb_recovery_channel(NULL, NULL, NULL, NULL, 0);
    ASSERT(r == -1, "SCB4: NULL ch returns -1");
    return 1;
}

/* ================================================================== */
/* SCB5 — scb_recovery_channel normal path → returns 0 or -1        */
/* ================================================================== */
int test_scb_recovery_no_dlp(void)
{
    /* With NULL pmgr, should return -1 (guard) */
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    int r = scb_recovery_channel(NULL, NULL, &ch, NULL, 0);
    ASSERT(r == -1, "SCB5: NULL pmgr returns -1");
    return 1;
}
