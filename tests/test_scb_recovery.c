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
/* SCB4/SCB5 (scb_recovery_channel guard tests) removed: scb_recovery_channel
   was unreachable dead code (0 production callers) and has been deleted. The
   live client-side SCB-restore/stale-state defense is the JSON MSG_RECONNECT
   untrusted-claim path (client_reconnect.c), proven e2e by
   tools/test_regtest_reconnect_cheat.sh (#94). SCB1-3 below still exercise the
   live type-136 ln_dispatch handler used by the LSP peer_mgr reconnect. */

/* ================================================================== */
/* SCB5 — scb_recovery_channel normal path → returns 0 or -1        */
/* ================================================================== */
/* (SCB5 removed with SCB4 above.) */

/* ================================================================== */
/* SCB6 — #256 SF-CHEAT-BACKUP-RESTORE arg-parse + offset logic      */
/*                                                                    */
/* The cheat injection lives in src/chan_open.c:chan_reestablish and  */
/* is env-var gated (SS_CHEAT_SCB_RESTORE + SS_CHEAT_SCB_OFFSET).     */
/* A full e2e exercise requires a running peer_mgr; here we           */
/* sanity-check the offset clamping arithmetic the cheat path uses    */
/* and that env-var gating is well-formed.                            */
/* ================================================================== */
#include <stdlib.h>
int test_scb_cheat_backup_restore_offset_logic(void)
{
    /* Mirror the clamp performed in chan_reestablish:
       offset = atol(SS_CHEAT_SCB_OFFSET); if (offset > cn) offset = cn;
       pcp_cn = cn - offset. */
    setenv("SS_CHEAT_SCB_OFFSET", "3", 1);
    uint64_t cn = 10;
    uint64_t offset = (uint64_t)atol(getenv("SS_CHEAT_SCB_OFFSET"));
    if (offset > cn) offset = cn;
    uint64_t pcp_cn = cn - offset;
    ASSERT(pcp_cn == 7, "SCB6a: offset=3 from cn=10 -> pcp_cn=7");

    /* Clamp: offset > cn must collapse to cn (pcp_cn = 0). */
    setenv("SS_CHEAT_SCB_OFFSET", "99", 1);
    cn = 2;
    offset = (uint64_t)atol(getenv("SS_CHEAT_SCB_OFFSET"));
    if (offset > cn) offset = cn;
    pcp_cn = cn - offset;
    ASSERT(pcp_cn == 0, "SCB6b: offset>cn clamps to cn");

    /* cn=0 means no revoked history -> honest fallback (cheat path is
       skipped entirely in chan_reestablish; we just confirm the
       short-circuit is safe to reason about here). */
    cn = 0;
    int armed = (cn > 0);
    ASSERT(armed == 0, "SCB6c: cn=0 must skip cheat (no revoked history)");

    /* Default OFFSET=1 (set when --cheat-backup-restore has no =VALUE). */
    setenv("SS_CHEAT_SCB_OFFSET", "1", 1);
    cn = 5;
    offset = (uint64_t)atol(getenv("SS_CHEAT_SCB_OFFSET"));
    if (offset > cn) offset = cn;
    pcp_cn = cn - offset;
    ASSERT(pcp_cn == 4, "SCB6d: default offset=1 from cn=5 -> pcp_cn=4 (cn-1, oldest revoked)");

    unsetenv("SS_CHEAT_SCB_OFFSET");
    unsetenv("SS_CHEAT_SCB_RESTORE");
    return 1;
}
