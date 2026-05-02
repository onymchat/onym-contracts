// Mobile-FFI for the SEP-Anarchy contract type.
//
// Hand-written to match `src/lib.rs`. See `../README.md` for the
// ABI contract — error model, byte-buffer ownership, scalar/point
// encoding. Clients link `sep-common-ffi` alongside this header for
// `onym_byte_buffer_free` / `onym_string_free` and shared hashing
// primitives.
//
// Witness inputs follow the leaf-hash + per-prover-secret-key shape
// (see ../README.md): mobile callers supply public-ish leaf
// hashes for the full member tree plus only the prover's own secret
// key. No other member's secret key crosses the FFI.

#ifndef ONYM_ANARCHY_FFI_H
#define ONYM_ANARCHY_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Mirrors `OnymByteBuffer` in sep-common-ffi. Both crates ship an
// identical #[repr(C)] layout; the free function lives only in
// sep-common-ffi.
typedef struct onym_byte_buffer_t {
    uint8_t *ptr;
    size_t len;
} onym_byte_buffer_t;

// ----- Bake VK -------------------------------------------------------------

// Bake the per-tier membership VK. Output: 3002-byte VK.
bool onym_anarchy_bake_membership_vk(size_t depth,
                                     onym_byte_buffer_t *out_vk,
                                     char **out_error);

// Bake the per-tier update VK. Output: 3002-byte VK.
bool onym_anarchy_bake_update_vk(size_t depth,
                                 onym_byte_buffer_t *out_vk,
                                 char **out_error);

// ----- Pinned VK SHA-256 hex ------------------------------------------------

// 64-char ASCII hex of the prover's pinned membership-VK SHA-256 for
// `depth`. Errors if `depth` is not a supported tier (5/8/11).
bool onym_anarchy_pinned_membership_vk_sha256_hex(size_t depth,
                                                  onym_byte_buffer_t *out_hex,
                                                  char **out_error);

bool onym_anarchy_pinned_update_vk_sha256_hex(size_t depth,
                                              onym_byte_buffer_t *out_hex,
                                              char **out_error);

// ----- Prove membership -----------------------------------------------------

// Generate a TurboPlonk anarchy-membership proof.
//
// Inputs:
//   member_leaf_hashes  — packed 32-byte BE Fr scalars
//                         (Poseidon(member_sk) per member, ≤ 2^depth).
//                         Public-ish derived values; SDKs already
//                         maintain these to know the visible tree
//                         state. No member's secret key crosses the
//                         FFI except the prover's own.
//   prover_secret_key   — prover's own 32-byte BE Fr scalar. The FFI
//                         sanity-checks Poseidon(prover_secret_key)
//                         against member_leaf_hashes[prover_index]
//                         before invoking the prover.
//   prover_index        — prover's slot in the leaf-hash roster.
//   epoch               — group epoch (commitment-bound public input).
//   salt                — 32 bytes; LE-mod-r in-circuit.
//
// Outputs:
//   out_proof       — 1601-byte uncompressed proof.
//   out_commitment  — 32 BE Fr (Poseidon(Poseidon(root, epoch), salt_fr)).
//
// Self-verifies before returning so witness/circuit-shape mismatches
// surface here, not after the proof ships to a contract.
bool onym_anarchy_prove_membership(size_t depth,
                                   const uint8_t *member_leaf_hashes_ptr,
                                   size_t member_leaf_hashes_len,
                                   const uint8_t *prover_secret_key_ptr,
                                   size_t prover_secret_key_len,
                                   size_t prover_index,
                                   uint64_t epoch,
                                   const uint8_t *salt_ptr,
                                   size_t salt_len,
                                   onym_byte_buffer_t *out_proof,
                                   onym_byte_buffer_t *out_commitment,
                                   char **out_error);

// ----- Prove update --------------------------------------------------------

// Generate a TurboPlonk anarchy-update proof.
//
// Inputs:
//   member_leaf_hashes_old   — old-tree leaf hashes (32 BE Fr each).
//   member_leaf_hashes_new   — new-tree leaf hashes. Pass EXACTLY
//                              {NULL, 0} to reuse the old roster (no
//                              roster change). Mixed states
//                              (NULL+nonzero, valid+zero) are
//                              rejected with a clear error so a
//                              caller-side input bug can't silently
//                              fall back to "no change". Circuit
//                              doesn't constrain new-tree membership;
//                              only the new root binds.
//   prover_secret_key        — prover's own secret key (32 BE Fr).
//   prover_index_old         — prover's slot in the old roster.
//   epoch_old                — old-commitment epoch (only epoch PI;
//                              new epoch is implicit epoch_old + 1).
//   salt_old, salt_new       — 32-byte salts; LE-mod-r in-circuit.
//
// Outputs:
//   out_proof          — 1601-byte uncompressed proof.
//   out_public_inputs  — 96 B = c_old (32 BE) || Fr::from(epoch_old)
//                        (32 BE) || c_new (32 BE), the exact vector
//                        the verifier consumes.
bool onym_anarchy_prove_update(size_t depth,
                               const uint8_t *member_leaf_hashes_old_ptr,
                               size_t member_leaf_hashes_old_len,
                               const uint8_t *member_leaf_hashes_new_ptr,
                               size_t member_leaf_hashes_new_len,
                               const uint8_t *prover_secret_key_ptr,
                               size_t prover_secret_key_len,
                               size_t prover_index_old,
                               uint64_t epoch_old,
                               const uint8_t *salt_old_ptr,
                               size_t salt_old_len,
                               const uint8_t *salt_new_ptr,
                               size_t salt_new_len,
                               onym_byte_buffer_t *out_proof,
                               onym_byte_buffer_t *out_public_inputs,
                               char **out_error);

#ifdef __cplusplus
}
#endif

#endif // ONYM_ANARCHY_FFI_H
