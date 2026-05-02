//! Binary Merkle authentication path verifier with Poseidon2-BN254-t3
//! 2-to-1 compression.
//!
//! ## Layout
//!
//! - **Digest**: a single BN254 `Fr` (32 bytes BE).
//! - **Leaf**: the codeword value at a given index, padded into the
//!   t=3 permutation state as `[value, 0, 0]`. The verifier always
//!   compresses through the t=3 permutation, so leaves and inner
//!   nodes share the same 1-element output shape.
//! - **Inner node**: `compress(L, R)` = first lane of
//!   `Poseidon2([L, R, 0])`. Capacity-1 absorbs of a 2-element pair
//!   give ~127-bit collision resistance, matching the transcript.
//! - **Root**: same shape as a node digest — single BN254 Fr.

use crate::field::{self, Fr};
use crate::host_poseidon2::Poseidon2Ctx;
use soroban_sdk::Env;

pub type Digest = Fr;

/// Errors path verification can raise.
#[derive(Debug, PartialEq, Eq)]
pub enum MerkleError {
    /// Path length doesn't match the declared tree depth, or path
    /// length is zero (collapsing a one-leaf tree is a special case
    /// clients must not exercise).
    BadPathLen,
    /// Reconstructed root does not match the expected root.
    RootMismatch,
}

/// Compress two digests via Poseidon2-t3.
/// `[left, right, 0] → permute → first lane`.
pub fn compress(env: &Env, ctx: &Poseidon2Ctx, left: &Digest, right: &Digest) -> Digest {
    let mut state = [left.clone(), right.clone(), field::zero(env)];
    ctx.permute(env, &mut state);
    state[0].clone()
}

/// Pad a single `Fr` value into the leaf shape used by the FRI
/// prover. With t=3 (rate 2) we treat the leaf hash as the value
/// itself — there's no "leaf compression" round needed for a single
/// scalar, since the tree's first level already compresses the
/// (sibling-left, sibling-right) pair.
pub fn leaf_digest_for(v: Fr) -> Digest {
    v
}

/// Verify a binary Merkle authentication path.
///
/// `index` is the leaf index (0-based). For each level, bit
/// `(index >> level) & 1` selects whether the sibling is on the
/// left (=1) or right (=0) of the current accumulator.
///
/// `siblings.len()` must equal the tree depth; trees of depth 0
/// (single leaf == root) aren't supported — clients shouldn't build
/// them.
pub fn verify_path(
    env: &Env,
    ctx: &Poseidon2Ctx,
    leaf: &Digest,
    index: u64,
    siblings: &[Digest],
    expected_root: &Digest,
) -> Result<(), MerkleError> {
    if siblings.is_empty() {
        return Err(MerkleError::BadPathLen);
    }
    let mut acc = leaf.clone();
    for (level, sib) in siblings.iter().enumerate() {
        let bit = (index >> level) & 1;
        if bit == 0 {
            acc = compress(env, ctx, &acc, sib);
        } else {
            acc = compress(env, ctx, sib, &acc);
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
    /// and return (leaves, root).
    fn build_tree(env: &Env, ctx: &Poseidon2Ctx, depth: usize) -> (Vec<Digest>, Digest) {
        let n = 1usize << depth;
        let mut leaves: Vec<Digest> = Vec::with_capacity(n);
        for i in 0..n {
            leaves.push(field::from_u32(env, (i as u32) * 17 + 1));
        }
        let mut layer = leaves.clone();
        while layer.len() > 1 {
            let mut next: Vec<Digest> = Vec::with_capacity(layer.len() / 2);
            for chunk in layer.chunks(2) {
                next.push(compress(env, ctx, &chunk[0], &chunk[1]));
            }
            layer = next;
        }
        (leaves, layer.into_iter().next().unwrap())
    }

    fn authentication_path(
        env: &Env,
        ctx: &Poseidon2Ctx,
        leaves: &[Digest],
        depth: usize,
        leaf_index: usize,
    ) -> Vec<Digest> {
        let mut layer: Vec<Digest> = leaves.to_vec();
        let mut path: Vec<Digest> = Vec::with_capacity(depth);
        let mut idx = leaf_index;
        for _ in 0..depth {
            let sib_idx = idx ^ 1;
            path.push(layer[sib_idx].clone());
            let mut next: Vec<Digest> = Vec::with_capacity(layer.len() / 2);
            for chunk in layer.chunks(2) {
                next.push(compress(env, ctx, &chunk[0], &chunk[1]));
            }
            layer = next;
            idx >>= 1;
        }
        path
    }

    #[test]
    fn accepts_canonical_path() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let (leaves, root) = build_tree(&env, &ctx, 3);
        for leaf_idx in 0..(1 << 3) {
            let path = authentication_path(&env, &ctx, &leaves, 3, leaf_idx);
            let result = verify_path(&env, &ctx, &leaves[leaf_idx], leaf_idx as u64, &path, &root);
            assert_eq!(result, Ok(()), "leaf {leaf_idx} path didn't verify");
        }
    }

    #[test]
    fn rejects_tampered_leaf() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let (leaves, root) = build_tree(&env, &ctx, 3);
        let bad_leaf = leaves[3].clone() + field::one(&env);
        let path = authentication_path(&env, &ctx, &leaves, 3, 3);
        assert_eq!(
            verify_path(&env, &ctx, &bad_leaf, 3, &path, &root),
            Err(MerkleError::RootMismatch),
        );
    }

    #[test]
    fn rejects_tampered_sibling() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let (leaves, root) = build_tree(&env, &ctx, 3);
        let mut path = authentication_path(&env, &ctx, &leaves, 3, 5);
        path[1] = path[1].clone() + field::one(&env);
        assert_eq!(
            verify_path(&env, &ctx, &leaves[5], 5, &path, &root),
            Err(MerkleError::RootMismatch),
        );
    }

    #[test]
    fn rejects_wrong_index() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let (leaves, root) = build_tree(&env, &ctx, 3);
        let path = authentication_path(&env, &ctx, &leaves, 3, 5);
        // Same path bytes, wrong index → wrong sibling-direction bits.
        assert_eq!(
            verify_path(&env, &ctx, &leaves[5], 4, &path, &root),
            Err(MerkleError::RootMismatch),
        );
    }

    #[test]
    fn empty_path_rejected() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let leaf = field::zero(&env);
        let root = leaf.clone();
        assert_eq!(
            verify_path(&env, &ctx, &leaf, 0, &[], &root),
            Err(MerkleError::BadPathLen),
        );
    }
}
