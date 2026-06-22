#ifndef SUPERSCALAR_CHEAT_GUARD_H
#define SUPERSCALAR_CHEAT_GUARD_H

/* #9: mainnet cheat/test-hook startup refusal (Layer 1).
 *
 * The repo carries dev/test/cheat options (--cheat-*, --test-*, --breach*,
 * --kill-after-*, --demo, and SS_CHEAT*/SS_KILL* env vars) that deliberately
 * bypass or weaken the security model.  None may EVER be reachable on mainnet.
 *
 * Two complementary layers enforce this:
 *   Layer 1 (this) — startup refusal: ss_find_mainnet_cheat() scans argv + the
 *     environment; on mainnet ANY such option => the daemon refuses to run.
 *     Prefix-based, so a future --cheat-X / SS_CHEAT_X is caught automatically
 *     (cannot be silently missed the way a scattered #ifdef can).
 *   Layer 2 (pre-existing) — superscalar_cheat_allowed() (crash_inject.h): the
 *     individual defense-bypass cheat read sites are inert unless on regtest,
 *     even if the env is set directly.  Defense in depth.
 *
 * Returns the offending argv token or "NAME=value" env string (for the error
 * message) when network is mainnet/bitcoin AND a dev/test/cheat option is
 * present; NULL otherwise (clean, or a non-mainnet network where these are
 * intentionally permitted).  A NULL/unknown network is treated as mainnet
 * (fail-safe).  The caller refuses to start on a non-NULL return.
 */
const char *ss_find_mainnet_cheat(int argc, char **argv, const char *network);

#endif /* SUPERSCALAR_CHEAT_GUARD_H */
