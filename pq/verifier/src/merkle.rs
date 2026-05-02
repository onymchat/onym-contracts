//! Binary Merkle authentication path verifier with Poseidon2-W16
//! 2-to-1 compression.
//!
//! ## Layout
//!
//! - **Leaf**: hash digest of 8 BabyBear elements (= 32 bytes).
//! - **Node**: Poseidon2-W16 permutation applied to a width-16 state
//!   loaded as `[left_8 | right_8]`, output digest = first 8 lanes.
//! - **Root**: same shape as a node digest — 8 BabyBear elements.
//!
//! This is the same shape Plonky3 uses for FRI / merkle-tree commits
//! (`p3_merkle_tree::FieldMerkleTree` with a Poseidon2 compressor).

use crate::field::Fr;
use crate::host_poseidon2::{permute, WIDTH};
use soroban_sdk::Env;

/// Digest is half the sponge width — 8 BabyBear elements. 8 × 31 ≈
/// 248 bits collision resistance, comfortably above the 128-bit floor.
pub const DIGEST_LEN: usize = 8;

pub type Digest = [Fr; DIGEST_LEN];

/// Errors path verification can raise.
#[derive(Debug, PartialEq, Eq)]
pub enum MerkleError {
    /// Path length doesn't match the declared tree depth, or path
    /// length is zero (which would mean leaf == root, which we
    /// disallow — collapsing a one-leaf tree is a special case clients
    /// must not exercise).
    BadPathLen,
    /// Reconstructed root does not match the expected root.
    RootMismatch,
}

/// Compress two `DIGEST_LEN`-wide digests into one via Poseidon2-W16.
/// `[left | right] -> permute -> first 8 lanes`.
pub fn compress(env: &Env, left: &Digest, right: &Digest) -> Digest {
    let mut state = [Fr::ZERO; WIDTH];
    state[..DIGEST_LEN].copy_from_slice(left);
    state[DIGEST_LEN..WIDTH].copy_from_slice(right);
    permute(env, &mut state);
    let mut out = [Fr::ZERO; DIGEST_LEN];
    out.copy_from_slice(&state[..DIGEST_LEN]);
    out
}

/// Verify a binary Merkle authentication path.
///
/// `index` is the leaf index (0-based, MSB == root-direction). For
/// each level, bit `(index >> level) & 1` selects whether the sibling
/// is on the left (=1) or right (=0) of the current accumulator.
///
/// `siblings.len()` must equal the tree depth. A depth-`d` tree has
/// `2^d` leaves and exactly `d` siblings on every authentication path.
pub fn verify_path(
    env: &Env,
    leaf: &Digest,
    index: u64,
    siblings: &[Digest],
    expected_root: &Digest,
) -> Result<(), MerkleError> {
    if siblings.is_empty() {
        return Err(MerkleError::BadPathLen);
    }
    let mut acc = *leaf;
    for (level, sib) in siblings.iter().enumerate() {
        let bit = (index >> level) & 1;
        if bit == 0 {
            acc = compress(env, &acc, sib);
        } else {
            acc = compress(env, sib, &acc);
        }
    }
    if &acc == expected_root {
        Ok(())
    } else {
        Err(MerkleError::RootMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    extern crate alloc;

    /// Build a deterministic depth-`d` tree from 2^d sequential leaves
    /// and return (leaves, root). Used to drive accept/reject
    /// authentication-path tests.
    fn build_tree(env: &Env, depth: usize) -> (Vec<Digest>, Digest) {
        let n = 1usize << depth;
        let mut leaves: Vec<Digest> = Vec::with_capacity(n);
        for i in 0..n {
            let mut leaf = [Fr::ZERO; DIGEST_LEN];
            for j in 0..DIGEST_LEN {
                leaf[j] = Fr::new((i as u32) * 17 + (j as u32) + 1);
            }
            leaves.push(leaf);
        }
        let mut layer = leaves.clone();
        while layer.len() > 1 {
            let mut next: Vec<Digest> = Vec::with_capacity(layer.len() / 2);
            for chunk in layer.chunks(2) {
                next.push(compress(env, &chunk[0], &chunk[1]));
            }
            layer = next;
        }
        (leaves, layer[0])
    }

    /// Build the authentication path for `leaf_index` under a depth-`d`
    /// tree built from `leaves`. Sibling at level `l` is the leaf-block
    /// adjacent to the accumulator at that level, which is the "other"
    /// half of the matching pair.
    fn authentication_path(
        env: &Env,
        leaves: &[Digest],
        depth: usize,
        leaf_index: usize,
    ) -> Vec<Digest> {
        let mut layer: Vec<Digest> = leaves.to_vec();
        let mut path: Vec<Digest> = Vec::with_capacity(depth);
        let mut idx = leaf_index;
        for _ in 0..depth {
            let sib_idx = idx ^ 1;
            path.push(layer[sib_idx]);
            let mut next: Vec<Digest> = Vec::with_capacity(layer.len() / 2);
            for chunk in layer.chunks(2) {
                next.push(compress(env, &chunk[0], &chunk[1]));
            }
            layer = next;
            idx >>= 1;
        }
        path
    }

    #[test]
    fn accepts_canonical_path() {
        let env = Env::default();
        let (leaves, root) = build_tree(&env, 4);
        for leaf_idx in 0..16 {
            let path = authentication_path(&env, &leaves, 4, leaf_idx);
            let result = verify_path(&env, &leaves[leaf_idx], leaf_idx as u64, &path, &root);
            assert_eq!(
                result,
                Ok(()),
                "canonical path for leaf {leaf_idx} should verify",
            );
        }
    }

    #[test]
    fn rejects_tampered_leaf() {
        let env = Env::default();
        let (leaves, root) = build_tree(&env, 3);
        let mut leaf = leaves[3];
        leaf[0] = leaf[0] + Fr::ONE;
        let path = authentication_path(&env, &leaves, 3, 3);
        assert_eq!(
            verify_path(&env, &leaf, 3, &path, &root),
            Err(MerkleError::RootMismatch),
        );
    }

    #[test]
    fn rejects_tampered_sibling() {
        let env = Env::default();
        let (leaves, root) = build_tree(&env, 3);
        let mut path = authentication_path(&env, &leaves, 3, 5);
        path[1][2] = path[1][2] + Fr::ONE;
        assert_eq!(
            verify_path(&env, &leaves[5], 5, &path, &root),
            Err(MerkleError::RootMismatch),
        );
    }

    #[test]
    fn rejects_wrong_index() {
        let env = Env::default();
        let (leaves, root) = build_tree(&env, 3);
        let path = authentication_path(&env, &leaves, 3, 5);
        // Same path bytes, wrong index → wrong sibling-direction bits.
        assert_eq!(
            verify_path(&env, &leaves[5], 4, &path, &root),
            Err(MerkleError::RootMismatch),
        );
    }

    #[test]
    fn empty_path_rejected() {
        let env = Env::default();
        let leaf = [Fr::ZERO; DIGEST_LEN];
        let root = leaf;
        assert_eq!(
            verify_path(&env, &leaf, 0, &[], &root),
            Err(MerkleError::BadPathLen),
        );
    }
}
