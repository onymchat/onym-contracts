# sep-oneonone-ffi

Mobile FFI for the **SEP-OneOnOne** contract type — two-party founding
groups, single tier (depth 5), no update path. Smallest of the per-type
FFI crates: 2 functions.

See [`../sep-common-ffi/README.md`](../sep-common-ffi/README.md) for
ABI conventions.

## What you get

```
                    SYMBOLS  (2 functions)
                    ══════════════════════

   onym_oneonone_bake_create_vk()      → 3002 B  (depth=5, single tier)

   onym_oneonone_prove_create(sk_0, sk_1, salt)
       → (1601 B proof, 32 B commitment)
```

## Founding ceremony

```
                  TWO PARTIES, ONE COMMITMENT
                  ═══════════════════════════

       Alice                                Bob
       sk_0                                 sk_1
         │                                   │
         │     ┌─────────────────────┐       │
         └────►│  prove_create       │◄──────┘
               │  (sk_0, sk_1, salt) │
               └──────────┬──────────┘
                          │
                          ▼
                    proof (1601 B)
                    commitment (32 B)
                          │
                          ▼
                  ship to sep-oneonone
                  contract create_group
```

## Why both keys appear here

The OneOnOne *create* moment is when both parties' keys have to be
present in one place — that's the founding ceremony. This is the one
deliberate exception to the leaf-hash + per-prover-secret-key shape used
by every other per-type FFI crate. Both `secret_key_0` and
`secret_key_1` cross the FFI boundary together, by design. After
create, neither key is ever needed again — the group is immutable.

The FFI rejects `secret_key_0 == secret_key_1` to prevent one-person
"1v1" groups (the upstream circuit doesn't enforce this gate today,
so the FFI does).

## Compatibility note

The commitment this returns is **bit-identical** to a depth-5 anarchy
membership commitment over the same `(root, epoch=0, salt)` triple. So
a 1v1 group is later verifiable as a depth-5 anarchy membership against
the shared anarchy `bake_membership_vk(5)`. (No explicit oneonone
membership FFI is needed.)

## Quick start

```c
#include "onym_common_ffi.h"
#include "onym_oneonone_ffi.h"

uint8_t alice_sk[32];
uint8_t bob_sk[32];
uint8_t salt[32];

onym_byte_buffer_t proof = {0}, commitment = {0};
char *err = NULL;

bool ok = onym_oneonone_prove_create(
    alice_sk, sizeof alice_sk,
    bob_sk,   sizeof bob_sk,
    salt,     sizeof salt,
    &proof, &commitment, &err);

if (!ok) {
    fprintf(stderr, "oneonone create failed: %s\n", err);
    onym_string_free(err);
    return 1;
}
onym_byte_buffer_free(proof);
onym_byte_buffer_free(commitment);
```

## Full signatures

[`include/onym_oneonone_ffi.h`](include/onym_oneonone_ffi.h)

## Build

```
cargo test --release   # 2 round-trip tests
```

Pinned to Rust 1.88.0 (matches `plonk/prover`).
