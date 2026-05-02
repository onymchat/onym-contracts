// Mobile-FFI for the SEP-Tyranny contract type. See
// ../README.md for the ABI contract.
//
// Witness inputs follow the leaf-hash + admin-secret-key shape: mobile
// callers supply public-ish leaf hashes for the full member tree plus
// only the admin's own secret key. No other member's secret key
// crosses the FFI.

#ifndef ONYM_TYRANNY_FFI_H
#define ONYM_TYRANNY_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Mirrors `OnymByteBuffer` in sep-common-ffi.
typedef struct onym_byte_buffer_t {
    uint8_t *ptr;
    size_t len;
} onym_byte_buffer_t;

bool onym_tyranny_bake_create_vk(size_t depth,
                                 onym_byte_buffer_t *out_vk,
                                 char **out_error);

bool onym_tyranny_bake_update_vk(size_t depth,
                                 onym_byte_buffer_t *out_vk,
                                 char **out_error);

bool onym_tyranny_pinned_create_vk_sha256_hex(size_t depth,
                                              onym_byte_buffer_t *out_hex,
                                              char **out_error);

bool onym_tyranny_pinned_update_vk_sha256_hex(size_t depth,
                                              onym_byte_buffer_t *out_hex,
                                              char **out_error);

// Generate a TurboPlonk tyranny-create proof.
//
// Inputs:
//   member_leaf_hashes — 32 BE Fr each (Poseidon(member_sk) per
//                        member). Admin's own leaf is at admin_index.
//   admin_secret_key   — admin's own 32 BE Fr scalar. The FFI
//                        sanity-checks Poseidon(admin_secret_key) ==
//                        member_leaf_hashes[admin_index].
//   admin_index        — admin's leaf position in the roster.
//   group_id_fr        — 32 BE Fr; per-group binding scalar.
//   salt               — 32 bytes; LE-mod-r in-circuit.
//
// Outputs:
//   out_proof          — 1601-byte uncompressed proof.
//   out_public_inputs  — 128 B = commitment(32) || Fr(0)(32)
//                        || admin_pubkey_commitment(32) || group_id_fr(32).
bool onym_tyranny_prove_create(size_t depth,
                               const uint8_t *member_leaf_hashes_ptr,
                               size_t member_leaf_hashes_len,
                               const uint8_t *admin_secret_key_ptr,
                               size_t admin_secret_key_len,
                               size_t admin_index,
                               const uint8_t *group_id_fr_ptr,
                               size_t group_id_fr_len,
                               const uint8_t *salt_ptr,
                               size_t salt_len,
                               onym_byte_buffer_t *out_proof,
                               onym_byte_buffer_t *out_public_inputs,
                               char **out_error);

// Generate a TurboPlonk tyranny-update proof.
//
// Inputs:
//   member_leaf_hashes_old — old-tree leaf hashes (32 BE Fr each).
//                            Admin must be at admin_index_old.
//   admin_secret_key       — admin's own secret key (32 BE Fr).
//   admin_index_old        — admin's leaf in the old roster.
//   epoch_old              — old commitment's epoch (only epoch PI;
//                            new epoch is implicit epoch_old + 1).
//   member_root_new        — 32 BE Fr; new tree's root, supplied
//                            directly (binding-only — admin needn't
//                            know full new roster).
//   group_id_fr            — 32 BE Fr.
//   salt_old, salt_new     — 32 each.
//
// Outputs:
//   out_proof          — 1601-byte proof.
//   out_public_inputs  — 160 B = c_old(32) || Fr(epoch_old)(32)
//                        || c_new(32) || admin_pubkey_commitment(32)
//                        || group_id_fr(32).
bool onym_tyranny_prove_update(size_t depth,
                               const uint8_t *member_leaf_hashes_old_ptr,
                               size_t member_leaf_hashes_old_len,
                               const uint8_t *admin_secret_key_ptr,
                               size_t admin_secret_key_len,
                               size_t admin_index_old,
                               uint64_t epoch_old,
                               const uint8_t *member_root_new_ptr,
                               size_t member_root_new_len,
                               const uint8_t *group_id_fr_ptr,
                               size_t group_id_fr_len,
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

#endif // ONYM_TYRANNY_FFI_H
