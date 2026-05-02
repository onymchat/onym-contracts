// Mobile-FFI for the SEP-OneOnOne contract type. See
// plonk/FFI-DESIGN.md for the ABI contract.

#ifndef ONYM_ONEONONE_FFI_H
#define ONYM_ONEONONE_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Mirrors `OnymByteBuffer` in sep-common-ffi (free function lives there).
typedef struct onym_byte_buffer_t {
    uint8_t *ptr;
    size_t len;
} onym_byte_buffer_t;

// Bake the depth=5 oneonone-create VK. Output: 3002 bytes.
bool onym_oneonone_bake_create_vk(onym_byte_buffer_t *out_vk,
                                  char **out_error);

// Generate a TurboPlonk oneonone-create proof.
//
// Inputs:
//   secret_key_0, secret_key_1 — 32 BE Fr each.
//   salt                       — 32 bytes; LE-mod-r in-circuit.
//
// Outputs:
//   out_proof       — 1601-byte uncompressed proof.
//   out_commitment  — 32 BE Fr (Poseidon(Poseidon(root, 0), salt_fr)).
//                     Bit-identical to a membership commitment over
//                     the same (root, epoch=0, salt), so the 1v1 group
//                     is later membership-verifiable against the
//                     depth-5 anarchy/democracy/oligarchy membership
//                     VK.
bool onym_oneonone_prove_create(const uint8_t *secret_key_0_ptr,
                                size_t secret_key_0_len,
                                const uint8_t *secret_key_1_ptr,
                                size_t secret_key_1_len,
                                const uint8_t *salt_ptr,
                                size_t salt_len,
                                onym_byte_buffer_t *out_proof,
                                onym_byte_buffer_t *out_commitment,
                                char **out_error);

#ifdef __cplusplus
}
#endif

#endif // ONYM_ONEONONE_FFI_H
