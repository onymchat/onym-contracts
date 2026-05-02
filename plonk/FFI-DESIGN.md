# Per-type FFI surface — design

This document pins the C ABI and Rust crate layout for the off-chain
prover's mobile-client FFI. It is the source of truth for every
`plonk/sep-*-ffi/` crate; symbol names, byte layouts, and ownership
rules below are part of the public contract and must not drift.

## Why this exists

The mobile SDKs (`onym-sdk-swift`, `onym-sdk-kotlin`) need to:

1. **Bake VKs** for each contract type/tier (so a freshly-deployed group
   can pin its verifier without a pre-shipped fixture).
2. **Generate proofs** locally for membership, update, and per-type
   admin paths.
3. **Compute primitives** (poseidon hashes, secp256k1 nostr signing,
   sha256 commitments, BLS12-381 pubkey derivation, plonk proof →
   contract-format conversion) without re-implementing them in
   Swift/Kotlin.

Until v0.1.5 the FFI lived in `stellar-mls/src/ffi.rs` and exposed a
single Groth16 surface. That crate (`sep-xxxx-circuits`) is being
deprecated. The new FFI is **TurboPlonk-only, per contract type**, and
lives next to the per-type Soroban contracts in `onym-contracts`.

## Crate layout

Four new crates under `plonk/`. Each is a standalone Cargo project (no
parent workspace, matching the existing `sep-anarchy/` pattern).

```
plonk/
  sep-common-ffi/        — shared primitives (poseidon, secp, sha256, …)
  sep-anarchy-ffi/       — bake_membership_vk, bake_update_vk, prove_*
  sep-oneonone-ffi/      — bake_oneonone_create_vk, prove_oneonone_create
  sep-tyranny-ffi/       — bake_tyranny_{create,update}_vk, prove_*
```

**`sep-democracy-ffi` and `sep-oligarchy-ffi` are intentionally not in
this PR.** Both circuits' quorum witnesses (`DemocracyUpdateQuorumWitness`,
`OligarchyUpdateQuorumWitness`) hold all K signers' secret keys in one
prover invocation — no FFI shape can avoid that without redesigning the
quorum verification model. Issue
[#26](https://github.com/onymchat/onym-contracts/issues/26) tracks the
strategic decision (larger SRS / vote aggregation via threshold sigs /
honest scope-down to K=2). The democracy + oligarchy mobile-FFI surface
ships once that decision lands.

Each crate:

- `crate-type = ["staticlib", "cdylib", "rlib"]` — staticlib for iOS
  XCFramework, cdylib for Android `.so`, rlib for Rust integration tests.
- `[dependencies] onym-plonk-prover = { path = "../prover" }`.
- Pins `rust-toolchain.toml` to `1.88.0` (matches the prover crate).
- Ships its own hand-written C header at `include/<crate>.h` and a
  `module.modulemap` for Swift consumption.

Mobile SDKs link **one of each per-type cdylib + the common cdylib**.
Per-type FFI symbols are `onym_<type>_*`; common FFI symbols are
`onym_*` (no per-type prefix). There is **no symbol collision** between
crates.

## ABI conventions

### Error model

Every fallible FFI function returns `bool` (`true` = success) and writes
an optional error message to `char **out_error`. On success, `*out_error
= NULL`. On failure, the callee allocates the C string with
`CString::into_raw`; the caller frees it with `onym_string_free`. Rust
panics that cross the boundary are caught and reported as
`"Rust panic crossed FFI boundary"` (verbatim).

```c
bool onym_<type>_bake_membership_vk(
    size_t depth,
    onym_byte_buffer_t *out_vk,
    char **out_error
);
```

### Byte buffers

```c
typedef struct onym_byte_buffer_t {
    uint8_t *ptr;
    size_t len;
} onym_byte_buffer_t;

void onym_byte_buffer_free(onym_byte_buffer_t buffer);
void onym_string_free(char *ptr);
```

The callee allocates with `Vec::into_raw_parts`-shaped semantics
(`buffer_from_vec(vec)`). The caller frees by passing the buffer back to
`onym_byte_buffer_free`. Mixing allocators across crates is safe because
all FFI crates are compiled with the same Rust toolchain and link against
the system allocator.

`onym_byte_buffer_free` and `onym_string_free` live in **sep-common-ffi**.
Per-type crates do not re-export them; clients always link sep-common-ffi.

### Scalar / point encoding

| Type                          | Bytes | Encoding                                              |
|-------------------------------|-------|-------------------------------------------------------|
| `Fr` (BLS12-381 scalar)       | 32    | Big-endian, `from_be_bytes_mod_order` (matches CLI)   |
| Salt                          | 32    | Little-endian, `from_le_bytes_mod_order` (in-circuit) |
| Compressed BLS12-381 G1 pubkey| 48    | arkworks compressed                                    |
| Uncompressed G1Affine         | 96    | arkworks uncompressed                                 |
| Uncompressed G2Affine         | 192   | arkworks uncompressed                                 |
| Plonk proof                   | 1601  | `Proof::serialize_uncompressed`                       |
| Plonk VK                      | 3002  | `VerifyingKey::serialize_uncompressed`                |
| `u64` epoch / count / threshold| (n/a)| Passed as native `uint64_t`                           |

The mixed BE/LE convention for scalars vs salts is preserved verbatim
from the prover crate — clients must follow it. Mismatches do not error
loudly; they produce silently-wrong commitments.

### Public-input concat shape

Every `prove_*` function that emits an `out_public_inputs` buffer
returns the **exact byte concat the plonk verifier consumes** — each
public input is a 32-byte BE Fr scalar, all packed contiguously, no
length prefixes. A function with N PIs writes 32 × N bytes; clients
slice by index. `u64` epochs / counts / thresholds appear as
`Fr::from(u64)` 32-byte BE-encoded, not as native `uint64_t` mid-buffer.
This keeps the buffer round-trippable to a future `onym_*_verify(vk,
public_inputs, proof)` FFI without re-encoding.

### Witness inputs (leaf-hash + per-prover-secret-key shape)

Mobile callers supply only:

- **`member_leaf_hashes`** — packed 32-byte BE Fr scalars
  (`Poseidon(member_sk)` per member, ≤ 2^depth entries). These are
  public-ish derived values that an SDK already maintains to know the
  visible member tree state. **Not** secret keys.
- The **prover's own secret key** (`prover_secret_key` for member
  proofs, `admin_secret_key` for admin proofs). 32-byte BE Fr.
- The **prover's leaf index** in the roster.
- Salts, epoch, group-id, etc. as needed per circuit type.

The FFI builds the merkle tree from leaf hashes, derives the prover's
path, threads the prover's secret key into the witness, and runs
preprocess + prove. **No member's secret key crosses the FFI except the
prover's own** — and only the prover, single-signer, ever runs the
proof. K-of-N quorum FFIs were intentionally dropped from this design
(see the crate-layout note above and issue #26).

The FFI sanity-checks `Poseidon(prover_secret_key) ==
member_leaf_hashes[prover_index]` before invoking the prover, so a
mismatch surfaces as a clear error rather than as `WrongProof` from
in-circuit constraint failure.

For the OneOnOne create circuit (two-party founding ceremony), both
parties' secret keys appear in the witness by design — the founding
moment is when both parties' keys are present in one place. The FFI
reflects this: `prove_create(secret_key_0, secret_key_1, salt)`.

## Per-type API

Each crate exposes:

- `onym_<type>_bake_*_vk(...)` — preprocesses the canonical witness for
  the requested tier and returns the serialized `VerifyingKey` bytes.
- `onym_<type>_pinned_*_vk_sha256_hex(...)` — returns the static
  SHA-256 hex string (32-char hex) the prover crate has pinned for this
  tier, or `false` + error if depth is unsupported.
- `onym_<type>_prove_*(...)` — synthesizes the circuit, preprocesses,
  proves, self-verifies, returns proof bytes (and any computed public
  inputs not already known to the caller, e.g. `commitment`).

### sep-common-ffi

```c
// Hashing
bool onym_compute_leaf_hash(const uint8_t *secret_key, size_t len,
    onym_byte_buffer_t *out, char **out_error);   // Poseidon(sk_fr) → 32 BE
bool onym_compute_public_key(const uint8_t *secret_key, size_t len,
    onym_byte_buffer_t *out, char **out_error);   // BLS12-381 G1 compressed (48)
bool onym_compute_merkle_root(const uint8_t *leaf_hashes, size_t len,
    size_t depth, onym_byte_buffer_t *out, char **out_error);

// Commitment
bool onym_compute_sha256_commitment(const uint8_t *root, size_t root_len,
    uint64_t epoch, const uint8_t *salt, size_t salt_len,
    onym_byte_buffer_t *out, char **out_error);
bool onym_compute_poseidon_commitment(const uint8_t *root, size_t root_len,
    uint64_t epoch, const uint8_t *salt, size_t salt_len,
    onym_byte_buffer_t *out, char **out_error);

// Plonk proof helpers
bool onym_parse_plonk_proof(const uint8_t *proof, size_t len,
    onym_byte_buffer_t *out_components_concat, char **out_error);
    // Returns wires(5×96) ++ prod_perm(96) ++ split_quot(5×96) ++
    //   opening(96) ++ shifted_opening(96) ++ wires_evals(5×32) ++
    //   wire_sigma_evals(4×32) ++ perm_next_eval(32). Caller slices.

// Nostr (secp256k1 schnorr — kept verbatim from v1 FFI)
bool onym_nostr_derive_public_key(const uint8_t *sk, size_t len,
    onym_byte_buffer_t *out, char **out_error);
bool onym_nostr_sign_event_id(const uint8_t *sk, size_t sk_len,
    const uint8_t *event_id, size_t event_id_len,
    onym_byte_buffer_t *out, char **out_error);
bool onym_nostr_verify_event_signature(const uint8_t *pk, size_t pk_len,
    const uint8_t *event_id, size_t event_id_len,
    const uint8_t *sig, size_t sig_len, char **out_error);

// Memory
void onym_byte_buffer_free(onym_byte_buffer_t buffer);
void onym_string_free(char *ptr);
```

### sep-anarchy-ffi

```c
bool onym_anarchy_bake_membership_vk(size_t depth,
    onym_byte_buffer_t *out_vk, char **out_error);
bool onym_anarchy_bake_update_vk(size_t depth,
    onym_byte_buffer_t *out_vk, char **out_error);
bool onym_anarchy_pinned_membership_vk_sha256_hex(size_t depth,
    onym_byte_buffer_t *out_hex, char **out_error);
bool onym_anarchy_pinned_update_vk_sha256_hex(size_t depth,
    onym_byte_buffer_t *out_hex, char **out_error);

bool onym_anarchy_prove_membership(
    size_t depth,
    const uint8_t *member_leaf_hashes_ptr, size_t member_leaf_hashes_len,
    const uint8_t *prover_secret_key_ptr, size_t prover_secret_key_len,
    size_t prover_index,
    uint64_t epoch,
    const uint8_t *salt_ptr, size_t salt_len,            // 32 LE
    onym_byte_buffer_t *out_proof,
    onym_byte_buffer_t *out_commitment,
    char **out_error);

bool onym_anarchy_prove_update(
    size_t depth,
    const uint8_t *member_leaf_hashes_old_ptr, size_t member_leaf_hashes_old_len,
    const uint8_t *member_leaf_hashes_new_ptr, size_t member_leaf_hashes_new_len, // {NULL,0} = reuse old
    const uint8_t *prover_secret_key_ptr, size_t prover_secret_key_len,
    size_t prover_index_old,
    uint64_t epoch_old,
    const uint8_t *salt_old_ptr, size_t salt_old_len,
    const uint8_t *salt_new_ptr, size_t salt_new_len,
    onym_byte_buffer_t *out_proof,
    onym_byte_buffer_t *out_public_inputs,               // 96 B = 3 BE Fr (c_old || Fr(epoch_old) || c_new)
    char **out_error);
```

### sep-oneonone-ffi

```c
bool onym_oneonone_bake_create_vk(onym_byte_buffer_t *out_vk, char **out_error);

// Two-party founding: both parties' secret keys appear in the witness
// by design — the create moment IS when both keys are present.
bool onym_oneonone_prove_create(
    const uint8_t *secret_key_0_ptr, size_t secret_key_0_len,
    const uint8_t *secret_key_1_ptr, size_t secret_key_1_len,
    const uint8_t *salt_ptr, size_t salt_len,
    onym_byte_buffer_t *out_proof,
    onym_byte_buffer_t *out_commitment,                  // 32 BE Fr
    char **out_error);
```

### sep-tyranny-ffi

```c
bool onym_tyranny_bake_create_vk(size_t depth,
    onym_byte_buffer_t *out_vk, char **out_error);
bool onym_tyranny_bake_update_vk(size_t depth,
    onym_byte_buffer_t *out_vk, char **out_error);
bool onym_tyranny_pinned_create_vk_sha256_hex(size_t depth,
    onym_byte_buffer_t *out_hex, char **out_error);
bool onym_tyranny_pinned_update_vk_sha256_hex(size_t depth,
    onym_byte_buffer_t *out_hex, char **out_error);

bool onym_tyranny_prove_create(
    size_t depth,
    const uint8_t *member_leaf_hashes_ptr, size_t member_leaf_hashes_len,
    const uint8_t *admin_secret_key_ptr, size_t admin_secret_key_len,
    size_t admin_index,
    const uint8_t *group_id_fr_ptr, size_t group_id_fr_len,   // 32 BE
    const uint8_t *salt_ptr, size_t salt_len,
    onym_byte_buffer_t *out_proof,
    onym_byte_buffer_t *out_public_inputs,                    // 128 B = 4 BE Fr
    char **out_error);

bool onym_tyranny_prove_update(
    size_t depth,
    const uint8_t *member_leaf_hashes_old_ptr, size_t member_leaf_hashes_old_len,
    const uint8_t *admin_secret_key_ptr, size_t admin_secret_key_len,
    size_t admin_index_old,
    uint64_t epoch_old,
    const uint8_t *member_root_new_ptr, size_t member_root_new_len,  // 32 BE Fr
    const uint8_t *group_id_fr_ptr, size_t group_id_fr_len,
    const uint8_t *salt_old_ptr, size_t salt_old_len,
    const uint8_t *salt_new_ptr, size_t salt_new_len,
    onym_byte_buffer_t *out_proof,
    onym_byte_buffer_t *out_public_inputs,                    // 160 B = 5 BE Fr
    char **out_error);
```

## Testing

Each crate ships:

- `tests/round_trip.rs` — for each `prove_*` function, run the FFI
  end-to-end (bake VK → prove → parse → verify against the baked VK
  using `onym_plonk_prover::prover::plonk::verify`) and assert success.
  Bake parity (FFI bake bytes match prover-native bake bytes) and
  pinned-VK SHA hex parity are folded into the same suite. Negative
  tests cover prover_secret_key / admin_secret_key mismatch (must
  surface a clear error before invoking the prover) and out-of-range
  prover_index.

## Build / CI

A new `.github/workflows/ffi.yml` runs `cargo test --release` for each
of the 4 crates on Linux. Cross-compilation to
`aarch64-apple-ios{,-sim}`, `aarch64-linux-android`,
`armv7-linux-androideabi`, etc. happens in the consumer SDK repos
(`onym-sdk-swift`, `onym-sdk-kotlin`); the FFI repo only verifies that
the host build + test passes.

Each crate's `Cargo.lock` is committed (matches existing per-contract
convention).

## What this design does NOT do

- **Does not provide opaque PK handles for caching across FFI calls.**
  Every `prove_*` call re-runs `preprocess()`. Caching is a follow-up
  if mobile profiles flag preprocess as the bottleneck (it almost
  certainly will, but the abstraction churn isn't worth it until we
  have numbers).
- **Does not bundle the SRS download.** The SRS is `include_bytes!`d
  by `onym-plonk-prover/build.rs`; FFI crates inherit that for free.
- **Does not export Groth16-format proof conversion.** The v1
  `sep_proof_to_contract_format` (decompresses 192-byte Groth16
  proofs) is not ported — Plonk proofs are 1601 bytes uncompressed and
  the Soroban contract parses them via `onym_parse_plonk_proof`.
- **Does not expose democracy / oligarchy quorum proofs.** The K-of-N
  quorum witnesses hold all K signers' secret keys in one prover
  invocation — operationally impossible in a mobile setting where
  signers can't share long-term keys. See issue #26.
- **Does not maintain wire compatibility with the v1 FFI.**
  Symbols that share names with v1 (`onym_compute_leaf_hash`,
  `onym_nostr_*`) are byte-for-byte compatible by accident, not by
  contract — clients should treat this as a fresh API.
