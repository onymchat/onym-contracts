// Shared mobile-FFI primitives for the onym-contracts sep-* family.
//
// Hand-written to match `src/lib.rs`. See `plonk/FFI-DESIGN.md` for the
// ABI contract — error model, byte-buffer ownership, scalar/point
// encoding, symbol naming.

#ifndef ONYM_COMMON_FFI_H
#define ONYM_COMMON_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Caller-owned byte buffer. Free via `onym_byte_buffer_free`.
typedef struct onym_byte_buffer_t {
    uint8_t *ptr;
    size_t len;
} onym_byte_buffer_t;

// Memory management. Both shared across every onym-* FFI crate; clients
// always link sep-common-ffi alongside the per-type crates.
void onym_byte_buffer_free(onym_byte_buffer_t buffer);
void onym_string_free(char *ptr);

// ----- Hashing primitives ---------------------------------------------------

// Poseidon(sk_fr) → 32-byte BE Fr scalar. `secret_key` is 32 BE bytes.
bool onym_compute_leaf_hash(const uint8_t *secret_key_ptr,
                            size_t secret_key_len,
                            onym_byte_buffer_t *out_leaf_hash,
                            char **out_error);

// BLS12-381 G1 compressed public key `[sk] · G` → 48 bytes.
bool onym_compute_public_key(const uint8_t *secret_key_ptr,
                             size_t secret_key_len,
                             onym_byte_buffer_t *out_public_key,
                             char **out_error);

// Poseidon Merkle root over `leaf_hashes` (tightly-packed 32 BE Fr,
// total length must be a multiple of 32, ≤ 2^depth scalars). Output
// is a 32-byte BE Fr scalar (the root).
bool onym_compute_merkle_root(const uint8_t *leaf_hashes_ptr,
                              size_t leaf_hashes_len,
                              size_t depth,
                              onym_byte_buffer_t *out_root,
                              char **out_error);

// ----- Commitment primitives ------------------------------------------------

// SHA-256 commitment: SHA256(root_be32 || epoch_be8 || salt). 32 bytes.
// Legacy v1 shape; for clients still talking to v1 sep-xxxx contracts.
bool onym_compute_sha256_commitment(const uint8_t *poseidon_root_ptr,
                                    size_t poseidon_root_len,
                                    uint64_t epoch,
                                    const uint8_t *salt_ptr,
                                    size_t salt_len,
                                    onym_byte_buffer_t *out_commitment,
                                    char **out_error);

// Poseidon commitment: Poseidon(Poseidon(root_fr, Fr::from(epoch)), salt_fr)
// where salt_fr = Fr::from_le_bytes_mod_order(salt). Output is the
// resulting Fr BE-encoded (32 bytes). `salt_len` must be 32.
bool onym_compute_poseidon_commitment(const uint8_t *poseidon_root_ptr,
                                      size_t poseidon_root_len,
                                      uint64_t epoch,
                                      const uint8_t *salt_ptr,
                                      size_t salt_len,
                                      onym_byte_buffer_t *out_commitment,
                                      char **out_error);

// ----- Plonk proof parser ---------------------------------------------------

// Strip the four `len()` u64 prefixes and trailing plookup-Option byte
// from a 1601-byte uncompressed jf-plonk proof. Returns 1568 bytes:
//
//   wires(5×96) ++ prod_perm(96) ++ split_quot(5×96) ++
//   opening(96) ++ shifted_opening(96) ++ wires_evals(5×32) ++
//   wire_sigma_evals(4×32) ++ perm_next_eval(32)
bool onym_parse_plonk_proof(const uint8_t *proof_ptr,
                            size_t proof_len,
                            onym_byte_buffer_t *out_components_concat,
                            char **out_error);

// ----- Nostr secp256k1 schnorr (BIP340) ------------------------------------

// 32-byte BIP340 x-only public key from a 32-byte secret.
bool onym_nostr_derive_public_key(const uint8_t *secret_key_ptr,
                                  size_t secret_key_len,
                                  onym_byte_buffer_t *out_public_key,
                                  char **out_error);

// BIP340 Schnorr signature over a 32-byte event id. Returns 64 bytes.
bool onym_nostr_sign_event_id(const uint8_t *secret_key_ptr,
                              size_t secret_key_len,
                              const uint8_t *event_id_ptr,
                              size_t event_id_len,
                              onym_byte_buffer_t *out_signature,
                              char **out_error);

// Verify a BIP340 Schnorr signature over a 32-byte event id. Returns
// `true` on a valid signature; `false` + populated `out_error` on
// invalid signature or malformed inputs.
bool onym_nostr_verify_event_signature(const uint8_t *public_key_ptr,
                                       size_t public_key_len,
                                       const uint8_t *event_id_ptr,
                                       size_t event_id_len,
                                       const uint8_t *signature_ptr,
                                       size_t signature_len,
                                       char **out_error);

#ifdef __cplusplus
}
#endif

#endif // ONYM_COMMON_FFI_H
