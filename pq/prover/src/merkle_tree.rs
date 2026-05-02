//! Binary Merkle tree *builder* — the prover-side counterpart of
//! `fri_verifier::merkle::verify_path`.
//!
//! ## Layout
//!
//! Same as the verifier:
//! - Leaves are `DIGEST_LEN`-wide digests. The FRI prover constructs
//!   each leaf as `[fr_value, 0, 0, 0, 0, 0, 0, 0]` — a single
//!   BabyBear value padded to 8 lanes — to match
//!   `fri_verifier::verifier::leaf_digest_for`. Trees of arbitrary
//!   8-lane leaves work the same way.
//! - Inner nodes are `Poseidon2(left_8 || right_8) → first 8 lanes`.
//!
//! ## Memory
//!
//! For our bench params (n_initial = 64, num_layers = 3) the largest
//! tree has 64 leaves → 127 nodes total → 4 KB. Trivial.
//!
//! Stored layer-major: `nodes[level]` is the array at depth `level`,
//! with `nodes[0]` the leaves and `nodes[depth]` the single root.
//! Each node is a `Digest` (8 BabyBear lanes).

use fri_verifier::merkle::{compress, Digest, DIGEST_LEN};
use fri_verifier::field::Fr;
use soroban_sdk::Env;

pub struct MerkleTree {
    /// `levels[0]` = leaves, `levels[depth]` = `[root]`.
    pub levels: Vec<Vec<Digest>>,
}

impl MerkleTree {
    /// Build a binary Merkle tree from leaf digests. `leaves.len()`
    /// must be a power of two ≥ 2.
    pub fn build(env: &Env, leaves: Vec<Digest>) -> Self {
        let n = leaves.len();
        assert!(n >= 2, "tree needs ≥ 2 leaves");
        assert!(n.is_power_of_two(), "leaf count must be power of 2");
        let mut levels = Vec::with_capacity(64);
        levels.push(leaves);
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next: Vec<Digest> = Vec::with_capacity(prev.len() / 2);
            for chunk in prev.chunks(2) {
                next.push(compress(env, &chunk[0], &chunk[1]));
            }
            levels.push(next);
        }
        MerkleTree { levels }
    }

    pub fn root(&self) -> Digest {
        self.levels.last().unwrap()[0]
    }

    /// Authentication path for `leaf_index`. Sibling at level `l` is
    /// the leaf-block adjacent to the accumulator at that level. The
    /// returned siblings are in ascending-level order to match
    /// `fri_verifier::merkle::verify_path` (which reads
    /// `siblings[level]` for level 0..depth).
    pub fn auth_path(&self, leaf_index: usize) -> Vec<Digest> {
        let depth = self.levels.len() - 1;
        let mut path = Vec::with_capacity(depth);
        let mut idx = leaf_index;
        for l in 0..depth {
            let sib_idx = idx ^ 1;
            path.push(self.levels[l][sib_idx]);
            idx >>= 1;
        }
        path
    }
}

/// Pad a single `Fr` into the leaf shape the FRI prover commits to:
/// `[v, 0, 0, 0, 0, 0, 0, 0]`. Mirrors
/// `fri_verifier::verifier::leaf_digest_for`.
pub fn leaf_digest_for(v: Fr) -> Digest {
    let mut d = [Fr::ZERO; DIGEST_LEN];
    d[0] = v;
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use fri_verifier::merkle::verify_path;

    #[test]
    fn auth_path_roundtrip() {
        let env = Env::default();
        let n = 16usize;
        let leaves: Vec<Digest> = (0..n)
            .map(|i| leaf_digest_for(Fr::new(i as u32 * 17 + 1)))
            .collect();
        let tree = MerkleTree::build(&env, leaves.clone());
        let root = tree.root();
        for i in 0..n {
            let path = tree.auth_path(i);
            assert_eq!(
                verify_path(&env, &leaves[i], i as u64, &path, &root),
                Ok(()),
                "leaf {i} path didn't verify",
            );
        }
    }

    #[test]
    fn tampered_leaf_rejects() {
        let env = Env::default();
        let leaves: Vec<Digest> = (0..8)
            .map(|i| leaf_digest_for(Fr::new(i as u32 + 1)))
            .collect();
        let tree = MerkleTree::build(&env, leaves.clone());
        let root = tree.root();
        let mut bad_leaf = leaves[3];
        bad_leaf[0] = bad_leaf[0] + Fr::ONE;
        let path = tree.auth_path(3);
        assert!(verify_path(&env, &bad_leaf, 3, &path, &root).is_err());
    }
}
