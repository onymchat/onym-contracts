# sep-anarchy-ffi

Mobile FFI for the **SEP-Anarchy** contract type — single-signer
membership groups (any member can advance the commitment).
Bake VKs, generate membership / update proofs, query pinned VK SHAs.

See [`../sep-common-ffi/README.md`](../sep-common-ffi/README.md) for
ABI conventions (error model, byte-buffer ownership, scalar encoding).

## What you get

```
                    SYMBOLS  (6 functions)
                    ══════════════════════

  ┌──────────────────────────────────────────────────────────┐
  │                       BAKE VK                            │
  │                                                          │
  │   onym_anarchy_bake_membership_vk(d)        → 3002 B    │
  │   onym_anarchy_bake_update_vk(d)            → 3002 B    │
  │                                                          │
  │   d = 5 / 8 / 11 (Small / Medium / Large tier)           │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │                  PINNED VK SHA-256 HEX                   │
  │                                                          │
  │   onym_anarchy_pinned_membership_vk_sha256_hex(d) → 64ch │
  │   onym_anarchy_pinned_update_vk_sha256_hex(d)     → 64ch │
  │                                                          │
  │   Static SHA the prover crate has pinned; matches        │
  │   SHA256(bake_*_vk(d)).                                  │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │                       PROVE                              │
  │                                                          │
  │   onym_anarchy_prove_membership(...)                     │
  │     → (1601 B proof, 32 B commitment)                    │
  │                                                          │
  │   onym_anarchy_prove_update(...)                         │
  │     → (1601 B proof, 96 B PI = c_old||epoch||c_new)      │
  └──────────────────────────────────────────────────────────┘
```

## Witness inputs (the privacy story)

You **don't** ship every member's secret key into the FFI. Only the
prover's own.

```
                    WHAT THE FFI WANTS
                    ══════════════════

   ┌─────────────────────────────────────────────────────────┐
   │  SDK side  (Swift / Kotlin)                             │
   │                                                         │
   │     member_leaf_hashes  =  Poseidon(member_sk) per      │
   │                            member, packed 32 BE bytes   │
   │                            each. Public-ish — the SDK   │
   │                            already has these to know    │
   │                            the visible tree state.      │
   │                                                         │
   │     prover_secret_key   =  the user's OWN 32 BE Fr.     │
   │                            Never any other member's.    │
   │                                                         │
   │     prover_index, epoch, salt, ...                      │
   └────────────────────────────┬────────────────────────────┘
                                │
                                │  cross FFI boundary
                                ▼
   ┌─────────────────────────────────────────────────────────┐
   │  FFI side  (Rust)                                       │
   │                                                         │
   │   1. Build merkle tree from leaf hashes                 │
   │   2. Sanity check: Poseidon(prover_sk) == leaves[idx]   │
   │      → mismatch = clear "leaf does not match" error,    │
   │        BEFORE invoking the prover.                      │
   │   3. Derive prover's path                               │
   │   4. Compose witness, synthesize, prove, self-verify    │
   │   5. Hand back proof bytes + commitment                 │
   └─────────────────────────────────────────────────────────┘
```

Get the leaf-key invariant wrong, you get a clear error string in
`out_error`. Get it right, you get a 1601-byte proof that the on-chain
verifier will accept.

## Quick start (membership)

```c
#include "onym_common_ffi.h"      // for onym_byte_buffer_t + free()
#include "onym_anarchy_ffi.h"

uint8_t leaves[32 * 8];           // 8 members at depth 5
uint8_t my_sk[32];                // your BLS12-381 BE secret key
size_t  my_index = 3;
uint64_t epoch = 0;
uint8_t  salt[32];                // 32 LE bytes (your per-state salt)

onym_byte_buffer_t proof = {0}, commitment = {0};
char *err = NULL;

bool ok = onym_anarchy_prove_membership(
    /* depth        */ 5,
    /* leaf_hashes  */ leaves, sizeof leaves,
    /* prover_sk    */ my_sk,  sizeof my_sk,
    /* prover_index */ my_index,
    /* epoch        */ epoch,
    /* salt         */ salt,   sizeof salt,
    /* outputs      */ &proof, &commitment, &err);

if (!ok) {
    fprintf(stderr, "anarchy membership proof failed: %s\n", err);
    onym_string_free(err);
    return 1;
}
// ship proof.ptr[0..proof.len] + commitment.ptr[0..32] to the contract
onym_byte_buffer_free(proof);
onym_byte_buffer_free(commitment);
```

## Update flow

```
                 prove_membership      prove_update
                 ════════════════      ════════════

      member       any member          any member
                   wants to read       wants to advance
                   off-chain           the commitment

      inputs       depth, leaves,      depth, leaves_old,
                   prover_sk,          (leaves_new | NULL),
                   prover_index,       prover_sk,
                   epoch, salt         prover_index_old,
                                       epoch_old,
                                       salt_old, salt_new

      circuit      Membership          Update
      VK           VK_d                UPDATE_VK_d
      gates        ~14k                ~14k

      output       proof (1601)        proof (1601)
      output       commitment (32)     PIs (96 = 3 × 32)

      epoch_new    n/a                 epoch_old + 1   (implicit)
```

Pass `member_leaf_hashes_new = NULL, len = 0` to reuse the old roster
(no membership change). Pass a different leaf-hash array to rotate
membership in the same update.

## Full signatures

[`include/onym_anarchy_ffi.h`](include/onym_anarchy_ffi.h)

## Build

```
cargo test --release   # 9 round-trip tests
```

Pinned to Rust 1.88.0 (matches `plonk/prover`). Each test exercises
prove → external-verify against the freshly-baked VK.
