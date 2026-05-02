# sep-tyranny-ffi

Mobile FFI for the **SEP-Tyranny** contract type — single-admin
governance (only the pinned admin can advance state). Bake VKs,
generate create / update proofs, query pinned VK SHAs.

See [`../sep-common-ffi/README.md`](../sep-common-ffi/README.md) for
ABI conventions.

## What you get

```
                    SYMBOLS  (6 functions)
                    ══════════════════════

  ┌──────────────────────────────────────────────────────────┐
  │                       BAKE VK                            │
  │                                                          │
  │   onym_tyranny_bake_create_vk(d)            → 3002 B    │
  │   onym_tyranny_bake_update_vk(d)            → 3002 B    │
  │                                                          │
  │   d = 5 / 8 / 11 (Small / Medium / Large tier)           │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │                  PINNED VK SHA-256 HEX                   │
  │                                                          │
  │   onym_tyranny_pinned_create_vk_sha256_hex(d)   → 64 ch  │
  │   onym_tyranny_pinned_update_vk_sha256_hex(d)   → 64 ch  │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │                       PROVE                              │
  │                                                          │
  │   onym_tyranny_prove_create(...)                         │
  │     → (1601 B proof, 128 B PI = 4 × 32 BE Fr)            │
  │                                                          │
  │   onym_tyranny_prove_update(...)                         │
  │     → (1601 B proof, 160 B PI = 5 × 32 BE Fr)            │
  └──────────────────────────────────────────────────────────┘
```

## What "tyranny" means here

```
              ADMIN BINDING  (the tyranny part)
              ═════════════════════════════════

       admin's secret key
              │
              │     Poseidon
              ▼
        admin pubkey
              │
              │     Poseidon( ─, group_id_fr )
              ▼
     admin_pubkey_commitment   ← ON-CHAIN (PI[2] of every update)
                                 binds this group to THIS admin

   * Different group → different group_id_fr → different commitment.
   * Same admin in two groups looks completely uncorrelated to anyone
     who doesn't know admin_sk.
   * Only the holder of admin_sk can produce a fresh proof that
     verifies against admin_pubkey_commitment + group_id_fr.
```

## Witness inputs

```
                  WHAT THE FFI WANTS  (admin path)
                  ════════════════════════════════

   member_leaf_hashes      Poseidon(member_sk) per member,
                           packed 32 BE bytes each. The admin's
                           leaf is one of these — at admin_index.
                           No member's secret key crosses the FFI
                           except the admin's own.

   admin_secret_key        admin's OWN 32 BE Fr scalar.
                           FFI sanity-checks
                             Poseidon(admin_secret_key)
                                == member_leaf_hashes[admin_index]
                           before invoking the prover.

   admin_index             admin's leaf position in the roster.

   group_id_fr             32 BE Fr; per-group binding scalar.
                           Typically Fr::from_be_bytes_mod_order
                           (group_id_bytes).
```

## Update flow

For `prove_update`, you also pass `member_root_new` directly (32 BE Fr)
— the admin doesn't need to know the new roster's full membership; the
circuit binds only the new root, not its preimage.

```
                 prove_create        prove_update
                 ════════════        ════════════

   admin           founds            advances commitment

   needs:          member roster     member roster (old) +
                                     member_root_new (32 B)

   PIs (out)       commitment        c_old
                   Fr(0)             Fr(epoch_old)
                   admin_pk_comm     c_new
                   group_id_fr       admin_pk_comm
                                     group_id_fr

                   = 128 B           = 160 B
                                     (epoch_new = epoch_old + 1
                                      enforced in-circuit)
```

## Quick start (create)

```c
#include "onym_common_ffi.h"
#include "onym_tyranny_ffi.h"

uint8_t leaves[32 * 8];            // 8 members at depth 5
uint8_t admin_sk[32];              // YOUR BE secret key
size_t  admin_index = 0;
uint8_t group_id_fr[32];           // 32 BE Fr derived from group_id
uint8_t salt[32];

onym_byte_buffer_t proof = {0}, public_inputs = {0};
char *err = NULL;

bool ok = onym_tyranny_prove_create(
    /* depth        */ 5,
    /* leaf_hashes  */ leaves,    sizeof leaves,
    /* admin_sk     */ admin_sk,  sizeof admin_sk,
    /* admin_index  */ admin_index,
    /* group_id_fr  */ group_id_fr, sizeof group_id_fr,
    /* salt         */ salt,      sizeof salt,
    /* outputs      */ &proof, &public_inputs, &err);

if (!ok) {
    fprintf(stderr, "tyranny create failed: %s\n", err);
    onym_string_free(err);
    return 1;
}
// public_inputs.ptr[0..32]  = commitment
//   "      "    .ptr[32..64] = Fr(0) (epoch)
//   "      "    .ptr[64..96] = admin_pubkey_commitment
//   "      "    .ptr[96..128]= group_id_fr
onym_byte_buffer_free(proof);
onym_byte_buffer_free(public_inputs);
```

## Full signatures

[`include/onym_tyranny_ffi.h`](include/onym_tyranny_ffi.h)

## Build

```
cargo test --release   # 7 round-trip tests
```

Pinned to Rust 1.88.0 (matches `plonk/prover`). Each prove test verifies
the FFI-produced proof under the freshly-baked tyranny VK end-to-end.
