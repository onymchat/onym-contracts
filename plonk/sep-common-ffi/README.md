# sep-common-ffi

Shared mobile-FFI primitives for the onym-contracts sep-* family.
Poseidon hashing, BLS12-381 G1 pubkey derivation, native Merkle root,
sha256 / poseidon commitment, plonk proof slicer, and Nostr secp256k1
schnorr — behind a stable C ABI for `onym-sdk-swift` and
`onym-sdk-kotlin`.

```
              SEP-* MOBILE FFI SUITE
              ══════════════════════

  ┌────────────────────────────────────────────────────┐
  │             sep-common-ffi   (this crate)          │
  │                                                    │
  │   onym_compute_leaf_hash       Poseidon(sk_fr)    │
  │   onym_compute_public_key      BLS12-381 G1 (48B) │
  │   onym_compute_merkle_root     tree-from-leaves   │
  │   onym_compute_sha256_commit   v1 commitment      │
  │   onym_compute_poseidon_commit plonk commitment   │
  │   onym_parse_plonk_proof       1601 → 1568 bytes  │
  │   onym_nostr_derive_pubkey     BIP340 secp256k1   │
  │   onym_nostr_sign_event_id     BIP340 schnorr sig │
  │   onym_nostr_verify_event_sig  BIP340 schnorr ver │
  │                                                    │
  │   onym_byte_buffer_free        free FFI buffer    │
  │   onym_string_free             free error string  │
  └────────────────────────────────────────────────────┘
                         ▲
                         │  every consumer links this
                         │  alongside one or more per-type crates
                         │
       ┌─────────────────┼─────────────────┐
       │                 │                 │
   ┌───┴────┐      ┌─────┴────┐      ┌─────┴────┐
   │anarchy │      │oneonone  │      │tyranny   │
   │  -ffi  │      │  -ffi    │      │  -ffi    │
   └────────┘      └──────────┘      └──────────┘
   sep-anarchy/    sep-oneonone/     sep-tyranny/
   README.md       README.md         README.md
```

## What's NOT here

`sep-democracy-ffi` and `sep-oligarchy-ffi` are intentionally absent.
Their K-of-N quorum witnesses hold all K signers' secret keys in one
prover invocation — operationally impossible in a mobile setting where
signers can't share long-term keys. See
[issue #26](https://github.com/onymchat/onym-contracts/issues/26) for
the strategic decision (larger SRS / threshold sigs / honest scope-down
to K=2).

## Linking

```
                LINK GRAPH (per app)
                ════════════════════

   libonym_sep_common_ffi.a      ← always linked
            +
   libonym_sep_<type>_ffi.a      ← one or more per type used
            +
   <your app .o>
            ↓
        binary

  No symbol collision: each per-type cdylib exports only its
  own onym_<type>_* symbols (verified in CI via `nm`); free /
  hashing / nostr live only in sep-common-ffi.
```

## ABI conventions

```
  Every fallible call:

      bool fn(...inputs..., onym_byte_buffer_t *out, char **out_error)

      true  → success, *out populated, *out_error == NULL
      false → failure, *out_error owns a CString describing the cause

  Memory ownership:

      onym_byte_buffer_t  → free with onym_byte_buffer_free
      char *out_error     → free with onym_string_free
      Both safe to call with NULL / {NULL,0}.
```

| Type                          | Bytes | Encoding                                            |
|-------------------------------|-------|-----------------------------------------------------|
| `Fr` (BLS12-381 scalar)       | 32    | Big-endian (`from_be_bytes_mod_order`)              |
| Salt                          | 32    | Little-endian (`from_le_bytes_mod_order`)           |
| Compressed BLS12-381 G1 pubkey| 48    | arkworks compressed                                 |
| Plonk proof                   | 1601  | `Proof::serialize_uncompressed`                     |
| Plonk VK                      | 3002  | `VerifyingKey::serialize_uncompressed`              |
| `u64` epoch / count           | (n/a) | Native `uint64_t`                                   |

`u64` values that appear inside `out_public_inputs` buffers are encoded
as `Fr::from(u64)` BE-32 (matches the verifier's input vector exactly).

## Quick start

```c
#include "onym_common_ffi.h"

uint8_t sk[32] = {/* your BLS12-381 secret key, BE */};
onym_byte_buffer_t leaf = {0};
char *err = NULL;

if (!onym_compute_leaf_hash(sk, sizeof sk, &leaf, &err)) {
    fprintf(stderr, "leaf hash failed: %s\n", err);
    onym_string_free(err);
    return 1;
}
// ... use leaf.ptr[0..leaf.len] (32 BE Fr bytes) ...
onym_byte_buffer_free(leaf);
```

Full C signatures for every symbol: see
[`include/onym_common_ffi.h`](include/onym_common_ffi.h).

## Build

Standalone Cargo workspace pinned to Rust 1.88.0 (matches `plonk/prover`):

```
cargo build --release   # produces libonym_sep_common_ffi.{a,dylib,so}
cargo test  --release   # 8 round-trip tests
```

The cdylib + staticlib drop in `target/release/`. Cross-compile to
iOS / Android targets in the consumer SDK repos (`onym-sdk-swift`,
`onym-sdk-kotlin`) — this crate is host-build-tested only.
