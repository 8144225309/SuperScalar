# SuperScalar CLN Plugin (skeleton)

Milestone 1 toward bLIP-56 integration (#172).

## What this is

A compilable, linkable skeleton for the Core Lightning (CLN) plugin that
will eventually expose SuperScalar's channel-factory machinery to a CLN
node over the bLIP-56 ("pluggable channel factories") protocol.

Files:

- `superscalar_cln.h` / `superscalar_cln.c` — public init / shutdown /
  message-dispatch surface. All entry points currently log a `STUB:`
  line and return success without touching real factory state.
- `blip56_codec.h` / `blip56_codec.c` — bLIP-56 message type IDs (mirror
  the existing `MSG_*` opcodes in `include/superscalar/wire.h`) plus
  trivial encode/decode stubs. Real TLV codec lives in `src/wire.c` and
  will be routed through once the send path is wired up.
- `CMakeLists.txt` — builds `libsuperscalar_cln.so` linked only against
  the existing static `libsuperscalar.a`. **No real CLN dependency yet.**

## What this is not

- Not loadable by `lightningd` yet. There is no plugin manifest, no
  JSON-RPC handlers, no `getmanifest` / `init` negotiation.
- No real factory operations performed. `superscalar_cln_handle_blip56_msg`
  decodes the type byte and prints what it *would* dispatch to.
- No bLIP-56 wire spec compliance beyond opcode numbering. Payload
  framing, TLV layout, and error semantics will be tightened against
  the spec under follow-up tasks.

## Build

The plugin is opt-in:

```
cmake -DBUILD_CLN_PLUGIN=ON -S . -B build-release
cmake --build build-release --target superscalar_cln
```

Default builds (`cmake -S . -B build-release`) are unaffected — no new
library, no new dependency.

## Roadmap

1. (this PR) Skeleton, opt-in build flag.
2. CLN plugin manifest + `getmanifest` / `init` JSON handlers.
3. Real bLIP-56 wire framing routed through `src/wire.c`.
4. Factory propose → ready loop driven by inbound bLIP-56 messages.
5. Splice gating (unblocks #198).
