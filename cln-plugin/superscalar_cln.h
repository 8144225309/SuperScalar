/* SuperScalar CLN plugin — public skeleton API.
 *
 * Skeleton only: types and signatures the eventual CLN plugin loader
 * will call. No real factory operations performed here yet (#172).
 *
 * Intentionally avoids including any CLN headers — the plugin loader
 * sees opaque pointers and the linker is free of CLN deps until the
 * real integration lands. */

#ifndef SUPERSCALAR_CLN_PLUGIN_H
#define SUPERSCALAR_CLN_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle representing the CLN plugin context. Real type lives
 * inside superscalar_cln.c; callers treat it as an abstract token. */
struct cln_plugin_handle;
typedef struct cln_plugin_handle cln_plugin_handle_t;

/* Return codes. Keep numeric values stable — they cross the FFI boundary. */
typedef enum {
    SCLN_OK            = 0,
    SCLN_ERR_INTERNAL  = 1,
    SCLN_ERR_BAD_MSG   = 2,
    SCLN_ERR_NOT_READY = 3,
} scln_status_t;

/* Plugin lifecycle. Returns NULL on allocation failure. */
cln_plugin_handle_t *superscalar_cln_init(void);
void                 superscalar_cln_shutdown(cln_plugin_handle_t *h);

/* Inbound bLIP-56 message dispatch.
 *
 * msg points to the raw wire frame (msg_type byte + payload). The handler
 * decodes via blip56_codec, dispatches to factory/channel logic, and may
 * produce zero or more reply frames via the (currently absent) send hook.
 *
 * Returns SCLN_OK on successful dispatch, error code otherwise. */
scln_status_t superscalar_cln_handle_blip56_msg(
    cln_plugin_handle_t *h,
    const uint8_t       *msg,
    size_t               msg_len
);

/* Plugin entry point. CLN's plugin manifest negotiation will call this
 * once the loader is wired up. Currently a stub that just records that
 * the plugin was loaded. */
int superscalar_cln_main(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* SUPERSCALAR_CLN_PLUGIN_H */
